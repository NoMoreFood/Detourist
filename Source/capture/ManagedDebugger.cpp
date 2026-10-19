#include "ManagedAttach.h"
#include "ManagedMetadata.h"
#include "DebuggerCallbacks.h"
#include <metahost.h>
#include <wrl/client.h>
#include <detours.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace Detourist
{
using Microsoft::WRL::ComPtr;

uintptr_t ContextIp(const CONTEXT& context)
{
#ifdef _WIN64
    return context.Rip;
#else
    return context.Eip;
#endif
}

bool AtBreakpointAddress(const CONTEXT& context, CORDB_ADDRESS address)
{
    // The stopped instruction pointer can follow the one-byte breakpoint.
    auto ip = ContextIp(context);
    return ip == address || ip == address + 1;
}

uintptr_t ContextSp(const CONTEXT& context)
{
#ifdef _WIN64
    return context.Rsp;
#else
    return context.Esp;
#endif
}

uint64_t ContextResult(const CONTEXT& context, CorElementType element)
{
#ifdef _WIN64
    return element == ELEMENT_TYPE_R4 || element == ELEMENT_TYPE_R8 ? context.Xmm0.Low : context.Rax;
#else
    // The debugger's saved floating-point registers contain the application's logical ST(0).
    if (element != ELEMENT_TYPE_R4 && element != ELEMENT_TYPE_R8)
        return element == ELEMENT_TYPE_I8 || element == ELEMENT_TYPE_U8 ?
            uint64_t{context.Eax} | (uint64_t{context.Edx} << 32) : context.Eax;
    auto source = (context.ContextFlags & CONTEXT_EXTENDED_REGISTERS) == CONTEXT_EXTENDED_REGISTERS ?
        context.ExtendedRegisters + 32 : context.FloatSave.RegisterArea;
    uint64_t value = 0;
    __asm { mov eax, source }
    __asm fld TBYTE PTR [eax]
    if (element == ELEMENT_TYPE_R4) __asm fstp DWORD PTR value
    else __asm fstp QWORD PTR value
    return value;
#endif
}

bool IsManagedReference(CorElementType element)
{
    return element == ELEMENT_TYPE_CLASS || element == ELEMENT_TYPE_OBJECT || element == ELEMENT_TYPE_STRING ||
        element == ELEMENT_TYPE_ARRAY || element == ELEMENT_TYPE_SZARRAY;
}

class DebuggerReadCache;
thread_local DebuggerReadCache* activeDebuggerReadCache = nullptr;

// Batch debugger reads while the runtime is stopped; mutations and continuation discard the snapshot.
class DebuggerReadCache
{
public:
    explicit DebuggerReadCache(DWORD process) : process_(process), previous_(activeDebuggerReadCache)
    {
        activeDebuggerReadCache = this;
    }
    ~DebuggerReadCache() { activeDebuggerReadCache = previous_; }
    void Clear() { pages_.clear(); }
    BOOL Read(HANDLE process, LPCVOID address, LPVOID buffer, SIZE_T count, SIZE_T* read)
    {
        if (process != handle_)
        {
            handle_ = process;
            allowed_ = GetProcessId(process) == process_;
        }
        auto cursor = reinterpret_cast<uint64_t>(address);
        if (!allowed_ || !buffer || !count || cursor < 65536 || count > CacheBytes ||
            cursor > UINT64_MAX - count || (cursor < 0x7FFF0000 && cursor + count > 0x7FFE0000))
            return ReadProcessMemory(process, address, buffer, count, read);
        auto destination = static_cast<BYTE*>(buffer);
        auto original = count;
        while (count)
        {
            auto page = cursor & ~(static_cast<uint64_t>(BlockBytes) - 1);
            auto offset = static_cast<size_t>(cursor - page);
            auto bytes = std::min<size_t>(count, BlockBytes - offset);
            auto found = pages_.find(page);
            if (found == pages_.end())
            {
                MEMORY_BASIC_INFORMATION information{};
                if (pages_.size() >= CacheBytes / BlockBytes ||
                    !VirtualQueryEx(process, reinterpret_cast<void*>(page), &information, sizeof(information)) ||
                    information.State != MEM_COMMIT || (information.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
                    reinterpret_cast<uint64_t>(information.BaseAddress) + information.RegionSize < page + BlockBytes)
                    return ReadProcessMemory(process, address, buffer, original, read);
                auto value = std::make_unique<std::array<BYTE, BlockBytes>>();
                SIZE_T copied = 0;
                if (!ReadProcessMemory(process, reinterpret_cast<void*>(page), value->data(), BlockBytes, &copied) ||
                    copied != BlockBytes) return ReadProcessMemory(process, address, buffer, original, read);
                found = pages_.emplace(page, std::move(value)).first;
            }
            memcpy(destination, found->second->data() + offset, bytes);
            cursor += bytes;
            destination += bytes;
            count -= bytes;
        }
        if (read) *read = original;
        return TRUE;
    }
    static void Invalidate()
    {
        if (activeDebuggerReadCache) activeDebuggerReadCache->Clear();
    }
    static BOOL WINAPI ReadMemory(HANDLE process, LPCVOID address, LPVOID buffer, SIZE_T count, SIZE_T* read)
    {
        try
        {
            if (activeDebuggerReadCache) return activeDebuggerReadCache->Read(process, address, buffer, count, read);
        }
        catch (...) {}
        return ReadProcessMemory(process, address, buffer, count, read);
    }
    static BOOL CALLBACK Import(PVOID, DWORD, PCSTR name, PVOID* function)
    {
        if (!name || !function || strcmp(name, "ReadProcessMemory")) return TRUE;
        DWORD protection = 0, ignored = 0;
        if (VirtualProtect(function, sizeof(*function), PAGE_READWRITE, &protection))
        {
            InterlockedExchangePointer(function, reinterpret_cast<void*>(&ReadMemory));
            VirtualProtect(function, sizeof(*function), protection, &ignored);
        }
        return TRUE;
    }
    static void Install()
    {
        static std::mutex mutex;
        std::lock_guard lock(mutex);
        if (auto module = GetModuleHandleW(L"mscordbi.dll"))
            DetourEnumerateImportsEx(module, nullptr, nullptr, &Import);
    }
private:
    static constexpr size_t BlockBytes = 65536, CacheBytes = 32 * 1024 * 1024;
    DWORD process_;
    HANDLE handle_ = nullptr;
    bool allowed_ = false;
    DebuggerReadCache* previous_;
    std::unordered_map<uint64_t, std::unique_ptr<std::array<BYTE, BlockBytes>>> pages_;
};

struct DebugMethod
{
    ManagedMethod metadata;
    std::vector<BYTE> resultSignature;
    ApiCategory category = ApiCategory::Unclassified;
    bool published = false;
    ULONG32 resultTypeIndex = UINT32_MAX;
    bool entryAbiKnown = false;
    bool instance = false;
    ULONG32 classParameters = 0;
    ULONG32 methodParameters = 0;
    ComPtr<ICorDebugModule> module;
    mdMethodDef token = 0;
    std::vector<ComPtr<ICorDebugFunctionBreakpoint>> entries;
    bool armed = false;
};

// Every active breakpoint adds to the runtime's per-stop inspection cost, so only selected methods carry one.
struct DebugSelection
{
    uint64_t categories = 0;
    bool all = false;
    LONG entryApi = -1, exitApi = -1;
    bool operator==(const DebugSelection&) const = default;
    explicit DebugSelection(const SharedHeader& header) :
        categories(header.enabledFilters & ManagedApis ? static_cast<uint64_t>(header.enabledFilters) >> 32 : 0),
        all(((header.entryBreaks | header.exitBreaks) & ManagedApis) != 0),
        entryApi(header.entryApi), exitApi(header.exitApi) {}
    bool Includes(const DebugMethod& method) const
    {
        const auto api = static_cast<LONG>(method.metadata.api);
        return all || (categories & CategoryMask(method.category)) || entryApi == api || exitApi == api;
    }
};

bool RecoverEntryContext(ICorDebugNativeFrame* frame, ICorDebugCode* code, const CONTEXT& stopped, CONTEXT& entry)
{
    // Optimized IL entry points can lack variable homes even when their prologue preserves every argument.
    CORDB_ADDRESS address = 0;
    ULONG32 offset = 0, count = 0;
    std::array<BYTE, 128 + 15> bytes{};
    if (!frame || !code || FAILED(code->GetAddress(&address)) || FAILED(frame->GetIP(&offset)) || !offset ||
        offset > 128 || !AtBreakpointAddress(stopped, address + offset) ||
        FAILED(code->GetCode(0, offset, offset, bytes.data(), &count)) || count != offset)
        return false;
    uint64_t stackBytes = 0;
    for (size_t position = 0; position < count;)
    {
        auto instruction = bytes.data() + position;
        auto next = static_cast<BYTE*>(DetourCopyInstruction(nullptr, nullptr, instruction, nullptr, nullptr));
        auto length = next ? static_cast<size_t>(next - instruction) : 0;
        if (!length || length > count - position) return false;
        position += length;
        size_t prefix = 0;
        auto rex = 0;
#ifdef _WIN64
        if (instruction[0] >= 0x40 && instruction[0] <= 0x4F) rex = instruction[prefix++];
#endif
        if (prefix >= length) return false;
        auto opcode = instruction[prefix];
        auto modrm = prefix + 1 < length ? instruction[prefix + 1] : 0;

        // Accept only straight-line stack setup and copies that leave incoming argument registers untouched.
        if (opcode >= 0x50 && opcode <= 0x57 && length == prefix + 1) stackBytes += sizeof(void*);
        else if (opcode == 0x90 && !(rex & 1) && length == prefix + 1) {}
        else if ((opcode == 0x8B || opcode == 0x89 || opcode == 0x8D) && prefix + 1 < length)
        {
            if (opcode != 0x8D && (modrm & 0xC0) != 0xC0) return false;
            if (opcode == 0x8D && (modrm & 0xC0) == 0xC0) return false;
            auto destination = opcode == 0x89 ? (modrm & 7) + ((rex & 1) ? 8 : 0) :
                ((modrm >> 3) & 7) + ((rex & 4) ? 8 : 0);
            if (destination == 1 || destination == 2 || destination == 4 || destination == 8 || destination == 9)
                return false;
        }
        else if ((sizeof(void*) == 4 || rex == 0x48) && modrm == 0xEC && (opcode == 0x81 || opcode == 0x83))
        {
            int32_t allocation = 0;
            auto immediateBytes = opcode == 0x81 ? sizeof(allocation) : 1;
            if (length != prefix + 2 + immediateBytes) return false;
            if (opcode == 0x81) memcpy(&allocation, instruction + prefix + 2, sizeof(allocation));
            else allocation = static_cast<int8_t>(instruction[prefix + 2]);
            if (allocation <= 0 || allocation > 1024 * 1024) return false;
            stackBytes += allocation;
        }
        else return false;
    }
    if (stackBytes > 1024 * 1024 || ContextSp(stopped) > UINT64_MAX - stackBytes) return false;
    entry = stopped;
#ifdef _WIN64
    entry.Rsp += stackBytes;
    entry.Rip = address;
#else
    entry.Esp += static_cast<DWORD>(stackBytes);
    entry.Eip = static_cast<DWORD>(address);
#endif
    return true;
}

struct DebugOutput
{
    CORDB_ADDRESS address = 0;
    CorElementType element = ELEMENT_TYPE_END;
    ULONG32 bytes = 0;
    ComPtr<ICorDebugHandleValue> root;
};

struct DebugInvocation
{
    DebugMethod* method = nullptr;
    Event event{};
    uint64_t stack = 0;
    CorElementType resultElement = ELEMENT_TYPE_END;
    ULONG32 resultBytes = 0;
    CORDB_ADDRESS nativeEntry = 0;
    ULONG32 nativeBytes = 0;
    CORDB_ADDRESS returnAddress = 0;
    bool hiddenContext = false;
    std::array<DebugOutput, MaximumArguments> outputs;
};

struct DebugStopPoint
{
    DebugMethod* method;
    bool leaving;
    ComPtr<ICorDebugFunctionBreakpoint> breakpoint;
    CORDB_ADDRESS address = 0;
    ComPtr<ICorDebugCode> entryCode;
    ULONG32 codeBytes = 0;
};

class RuntimeDebugger final : public ManagedDebugger, public DebuggerCallbacks
{
public:
    explicit RuntimeDebugger(Transport& transport) : transport_(transport), selection_(*transport.Header()) {}
    ~RuntimeDebugger() override { Shutdown(); }
    HRESULT Initialize(DWORD processId, const std::wstring& runtime, bool legacy);
    void Refresh() override;
    HRESULT Shutdown() override;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = nullptr;
        if (iid == IID_IUnknown || iid == __uuidof(ICorDebugManagedCallback))
            *value = static_cast<ICorDebugManagedCallback*>(this);
        else if (iid == __uuidof(ICorDebugManagedCallback2))
            *value = static_cast<ICorDebugManagedCallback2*>(this);
        else return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    HRESULT STDMETHODCALLTYPE CreateProcess(ICorDebugProcess* process) override
    {
        process_ = process;
        return process->Continue(FALSE);
    }
    HRESULT STDMETHODCALLTYPE ExitProcess(ICorDebugProcess*) override
    {
        exited_ = true;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE DebuggerError(ICorDebugProcess*, HRESULT, DWORD) override
    {
        transport_.Header()->managedState = static_cast<LONG>(ManagedState::Failed);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE LoadModule(ICorDebugAppDomain* domain, ICorDebugModule* module) override;
    HRESULT STDMETHODCALLTYPE Breakpoint(ICorDebugAppDomain* domain, ICorDebugThread* thread,
        ICorDebugBreakpoint* breakpoint) override;
    HRESULT STDMETHODCALLTYPE ExitThread(ICorDebugAppDomain* domain, ICorDebugThread* thread) override;
private:
    void Arm(DebugMethod& method, bool armed);
    void InstallNativeCode(DebugMethod* method, ICorDebugCode* code);
    void Enter(DebugMethod* method, ICorDebugThread* thread, ICorDebugFrame* frame, const CONTEXT& context,
        CORDB_ADDRESS nativeEntry = 0, ULONG32 nativeBytes = 0);
    void ReadEntryArgument(uint32_t index, ICorDebugThread* thread, ComPtr<ICorDebugNativeFrame>& frame,
        const CONTEXT& context, DebugInvocation& call, ComPtr<ICorDebugHeapValue2>& root);
    void Leave(DebugMethod* method, DWORD threadId, ICorDebugThread* thread, ICorDebugNativeFrame* frame,
        const CONTEXT& context);
    void EndTop(DWORD threadId, uint32_t flags);
    void Publish(Event event, const std::vector<std::byte>& payload);
    void PublishMetadata(DebugMethod& method);
    bool WaitForResume();
    void Hold(Event& event, bool leaving);
    void Snapshot(uint32_t parameter, ValueKind kind, const void* data, uint64_t size, bool readable = true,
        uint32_t stride = 0);
    void ReadValue(uint32_t parameter, ICorDebugValue* value, uint64_t& scalar, uint32_t depth = 0);
    bool ReadHeapValue(uint32_t parameter, uint64_t address);
    void CaptureStack(ICorDebugThread* thread);
    Transport& transport_;
    ComPtr<ICorDebug> debugger_;
    ComPtr<ICorDebugProcess> process_;
    std::atomic<ULONG> references_ = 1;
    std::atomic<bool> held_ = false;
    std::atomic<bool> closing_ = false;
    std::atomic<bool> exited_ = false;
    bool legacy_ = false;
    std::recursive_mutex callbacks_;
    std::unordered_map<ICorDebugBreakpoint*, DebugStopPoint> points_;
    std::vector<ICorDebugFunctionBreakpoint*> created_;
    std::unordered_map<DWORD, std::vector<DebugInvocation>> threads_;
    std::unordered_set<CORDB_ADDRESS> nativeCode_;
    std::vector<std::unique_ptr<DebugMethod>> methods_;
    DebugSelection selection_;
    std::vector<std::byte> payload_, scratch_;
    uint32_t limit_ = 0;
    HRESULT shutdownResult_ = S_OK;
};

HRESULT RuntimeDebugger::Initialize(DWORD processId, const std::wstring& runtime, bool legacy)
{
    legacy_ = legacy;
    // Use the debugger implementation that matches the runtime already loaded in the target.
    HRESULT result = S_OK;
    if (legacy)
    {
        auto directory = std::filesystem::path(runtime).parent_path();
        auto runtimeModule = LoadLibraryExW(runtime.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        auto module = runtimeModule ? LoadLibraryExW((directory / L"mscordbi.dll").c_str(), nullptr,
            LOAD_WITH_ALTERED_SEARCH_PATH) : nullptr;
        auto create = module ? reinterpret_cast<HRESULT(STDAPICALLTYPE*)(int, IUnknown**)>(
            GetProcAddress(module, "CreateCordbObject")) : nullptr;
        if (!create) return HRESULT_FROM_WIN32(GetLastError());
        ComPtr<IUnknown> unknown;
        result = create(CorDebugVersion_2_0, &unknown);
        if (SUCCEEDED(result)) result = unknown.As(&debugger_);
    }
    else
    {
        auto module = LoadLibraryExW(L"mscoree.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        auto create = module ? reinterpret_cast<HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**)>(
            GetProcAddress(module, "CLRCreateInstance")) : nullptr;
        if (!create) return HRESULT_FROM_WIN32(GetLastError());
        ComPtr<ICLRMetaHost> metadata;
        result = create(CLSID_CLRMetaHost, IID_ICLRMetaHost, reinterpret_cast<void**>(metadata.GetAddressOf()));
        ComPtr<ICLRRuntimeInfo> information;
        if (SUCCEEDED(result)) result = metadata->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo,
            reinterpret_cast<void**>(information.GetAddressOf()));
        if (SUCCEEDED(result)) result = information->GetInterface(CLSID_CLRDebuggingLegacy, __uuidof(ICorDebug),
            reinterpret_cast<void**>(debugger_.GetAddressOf()));
    }
    if (SUCCEEDED(result)) result = debugger_->Initialize();
    if (SUCCEEDED(result)) DebuggerReadCache::Install();
    if (SUCCEEDED(result)) result = debugger_->SetManagedHandler(static_cast<ICorDebugManagedCallback*>(this));
    if (SUCCEEDED(result))
    {
        transport_.Header()->managedState = static_cast<LONG>(ManagedState::Attaching);
        result = debugger_->DebugActiveProcess(processId, FALSE, &process_);
    }
    return result;
}

HRESULT RuntimeDebugger::LoadModule(ICorDebugAppDomain* domain, ICorDebugModule* module)
{
    std::lock_guard lock(callbacks_);
    try
    {
        if (!closing_)
        {
            std::wstring path(ExtendedPathCapacity, L'\0');
            ULONG32 length = 0;
            if (SUCCEEDED(module->GetName(static_cast<ULONG32>(path.size()), &length, path.data())) && length)
            {
                path.resize(length - 1);
                ComPtr<IMetaDataImport> metadata;
                if (FrameworkModule(path) && SUCCEEDED(module->GetMetaDataInterface(IID_IMetaDataImport,
                    reinterpret_cast<IUnknown**>(metadata.GetAddressOf()))) && FrameworkIdentity(metadata.Get()))
                {
                    ComPtr<IMetaDataImport2> genericMetadata;
                    metadata->QueryInterface(IID_IMetaDataImport2,
                        reinterpret_cast<void**>(genericMetadata.GetAddressOf()));
                    // Install IL breakpoints for existing code and methods compiled after attachment.
                    HCORENUM enumeration = nullptr;
                    mdTypeDef types[128];
                    ULONG count = 0;
                    while (!closing_ && SUCCEEDED(metadata->EnumTypeDefs(&enumeration, types, 128, &count)) && count)
                    {
                        for (ULONG type = 0; type < count && !closing_; ++type)
                        {
                            ULONG classParameters = 0, fetched = 0;
                            HCORENUM parameters = nullptr;
                            mdGenericParam parameter = 0;
                            if (genericMetadata && SUCCEEDED(genericMetadata->EnumGenericParams(&parameters,
                                types[type], &parameter, 1, &fetched)))
                                genericMetadata->CountEnum(parameters, &classParameters);
                            if (parameters) metadata->CloseEnum(parameters);
                            HCORENUM methodEnumeration = nullptr;
                            mdMethodDef tokens[128];
                            ULONG methodCount = 0;
                            while (!closing_ && SUCCEEDED(metadata->EnumMethods(&methodEnumeration, types[type],
                                tokens, 128, &methodCount)) && methodCount)
                            {
                                for (ULONG index = 0; index < methodCount && !closing_; ++index)
                                {
                                    ComPtr<ICorDebugFunction> function;
                                    ComPtr<ICorDebugCode> code;
                                    if (FAILED(module->GetFunctionFromToken(tokens[index], &function)) ||
                                        FAILED(function->GetILCode(&code)) || !code) continue;
                                    auto method = std::make_unique<DebugMethod>();
                                    if (!ReadManagedMethod(metadata.Get(), path, tokens[index], method->metadata,
                                        &method->resultSignature)) continue;
                                    method->module = module;
                                    method->token = tokens[index];
                                    method->metadata.api =
                                        ManagedDebuggerApiStart + static_cast<uint32_t>(methods_.size());
                                    method->category = ClassifyApi(Utf8(method->metadata.moduleName).c_str(),
                                        Utf8(method->metadata.name).c_str());

                                    // Enum arguments and results follow their metadata field's scalar representation.
                                    auto resolveEnum = [&](ManagedType& value)
                                    {
                                        if (value.element != ELEMENT_TYPE_VALUETYPE) return;
                                        mdTypeDef definition = 0;
                                        mdFieldDef field = 0;
                                        mdToken base = 0;
                                        ULONG nameBytes = 0, bytes = 0;
                                        wchar_t name[512]{};
                                        PCCOR_SIGNATURE signature = nullptr;
                                        auto typeName = value.name;
                                        if (value.byReference) typeName.pop_back();
                                        if (FAILED(metadata->FindTypeDefByName(typeName.c_str(), mdTokenNil,
                                            &definition)) || FAILED(metadata->GetTypeDefProps(definition, nullptr, 0,
                                            &nameBytes, nullptr, &base))) return;
                                        if (TypeFromToken(base) == mdtTypeRef)
                                            metadata->GetTypeRefProps(base, nullptr, name, _countof(name), &nameBytes);
                                        else if (TypeFromToken(base) == mdtTypeDef)
                                            metadata->GetTypeDefProps(base, name, _countof(name), &nameBytes, nullptr,
                                                nullptr);
                                        if (wcscmp(name, L"System.Enum") ||
                                            FAILED(metadata->FindField(definition, L"value__", nullptr, 0, &field)) ||
                                            FAILED(metadata->GetFieldProps(field, nullptr, nullptr, 0, &nameBytes,
                                                nullptr, &signature, &bytes, nullptr, nullptr, nullptr)) ||
                                            bytes != 2 || signature[0] != IMAGE_CEE_CS_CALLCONV_FIELD) return;
                                        auto element = static_cast<CorElementType>(signature[1]);
                                        uint32_t size = element == ELEMENT_TYPE_I1 || element == ELEMENT_TYPE_U1 ? 1 :
                                            element == ELEMENT_TYPE_I2 || element == ELEMENT_TYPE_U2 ? 2 :
                                            element == ELEMENT_TYPE_I4 || element == ELEMENT_TYPE_U4 ? 4 :
                                            element == ELEMENT_TYPE_I8 || element == ELEMENT_TYPE_U8 ? 8 : 0;
                                        if (!size) return;
                                        value.element = element;
                                        if (value.byReference) value.referencedBytes = size;
                                        else value.bytes = size;
                                    };
                                    for (auto& argument : method->metadata.arguments) resolveEnum(argument);
                                    resolveEnum(method->metadata.result);
                                    const auto& resultType = method->metadata.result;
                                    if (resultType.element == ELEMENT_TYPE_VAR ||
                                        resultType.element == ELEMENT_TYPE_MVAR)
                                        method->resultTypeIndex = static_cast<ULONG32>(std::stoul(
                                            resultType.name.substr(resultType.element == ELEMENT_TYPE_VAR ? 1 : 2))) +
                                            (resultType.element == ELEMENT_TYPE_MVAR ? classParameters : 0);

                                    // Direct entry capture requires a known register representation.
                                    PCCOR_SIGNATURE signature = nullptr;
                                    ULONG signatureBytes = 0;
                                    DWORD attributes = 0;
                                    mdToken base = 0;
                                    metadata->GetTypeDefProps(types[type], nullptr, 0, nullptr, nullptr, &base);
                                    auto isValueType = IsValueTypeBase(metadata.Get(), base);
                                    method->entryAbiKnown = SUCCEEDED(metadata->GetMethodProps(tokens[index], nullptr,
                                        nullptr, 0, nullptr, &attributes, &signature, &signatureBytes, nullptr,
                                        nullptr)) && signatureBytes &&
                                        (signature[0] & IMAGE_CEE_CS_CALLCONV_MASK) == IMAGE_CEE_CS_CALLCONV_DEFAULT &&
                                        (!isValueType || (attributes & mdStatic)) &&
                                        (resultType.element == ELEMENT_TYPE_VOID || resultType.bytes ||
                                            method->resultTypeIndex != UINT32_MAX) &&
                                        std::all_of(method->metadata.arguments.begin(),
                                            method->metadata.arguments.end(),
                                            [](const ManagedType& value) { return value.bytes != 0; });
                                    method->instance = !(attributes & mdStatic);
                                    method->classParameters = classParameters;
                                    if (signatureBytes > 1 && (signature[0] & IMAGE_CEE_CS_CALLCONV_GENERIC))
                                    {
                                        auto parameterCount = signature + 1;
                                        method->methodParameters = CorSigUncompressData(parameterCount);
                                    }
                                    Arm(*method, selection_.Includes(*method));
                                    methods_.push_back(std::move(method));
                                }
                            }
                            metadata->CloseEnum(methodEnumeration);
                        }
                    }
                    metadata->CloseEnum(enumeration);
                }
            }
            transport_.Header()->managedState = static_cast<LONG>(ManagedState::Active);
        }
    }
    catch (...) { transport_.Header()->managedState = static_cast<LONG>(ManagedState::Failed); }
    return domain->Continue(FALSE);
}

void RuntimeDebugger::Arm(DebugMethod& method, bool armed)
{
    if (method.armed == armed) return;
    if (!armed || !method.entries.empty())
    {
        for (auto& entry : method.entries) entry->Activate(armed);
        method.armed = armed;
        return;
    }

    // The IL entry breakpoint covers future compilations; legacy runtimes also stop at known native entries.
    ComPtr<ICorDebugFunction> function;
    ComPtr<ICorDebugCode> code, native;
    ComPtr<ICorDebugFunctionBreakpoint> breakpoint;
    if (FAILED(method.module->GetFunctionFromToken(method.token, &function)) || FAILED(function->GetILCode(&code)) ||
        !code || FAILED(code->CreateBreakpoint(0, &breakpoint)) || FAILED(breakpoint->Activate(TRUE))) return;
    points_.emplace(breakpoint.Get(), DebugStopPoint{&method, false, breakpoint});
    created_.push_back(breakpoint.Get());
    method.entries.push_back(breakpoint);
    method.armed = true;
    if (legacy_ && method.entryAbiKnown && SUCCEEDED(function->GetNativeCode(&native)) && native)
        InstallNativeCode(&method, native.Get());
}

void RuntimeDebugger::Refresh()
{
    // Changing breakpoints requires a synchronized runtime, so follow the filters only when they change.
    DebugSelection selection(*transport_.Header());
    if (selection == selection_ || closing_ || held_ || !process_ || FAILED(process_->Stop(5000))) return;
    {
        std::lock_guard lock(callbacks_);
        selection_ = selection;
        for (auto& method : methods_) Arm(*method, selection.Includes(*method));
    }
    process_->Continue(FALSE);
}

void RuntimeDebugger::InstallNativeCode(DebugMethod* method, ICorDebugCode* code)
{
    CORDB_ADDRESS address = 0;
    if (!code || FAILED(code->GetAddress(&address)) || !address ||
        nativeCode_.contains(address)) return;
    ULONG32 size = 0, count = 0;
    if (FAILED(code->GetSize(&size)) || size > 16 * 1024 * 1024) return;
    std::vector<BYTE> bytes(static_cast<size_t>(size) + 15, 0);
    if (FAILED(code->GetCode(0, size, size, bytes.data(), &count))) return;

    // Preserve IL breakpoints for future compilations and generic bodies not represented by this native code.
    if (method->entryAbiKnown && count && bytes[0] != 0xC3 && bytes[0] != 0xC2 &&
        !(bytes[0] == 0xF3 && count > 1 && bytes[1] == 0xC3))
    {
        ComPtr<ICorDebugFunctionBreakpoint> entry;
        DebuggerReadCache::Invalidate();
        if (SUCCEEDED(code->CreateBreakpoint(0, &entry)) && SUCCEEDED(entry->Activate(TRUE)))
        {
            points_.emplace(entry.Get(), DebugStopPoint{method, false, entry, address, code, size});
            created_.push_back(entry.Get());
            method->entries.push_back(entry);
        }
        DebuggerReadCache::Invalidate();
    }

    // Decode copied code without following its indirect references into the debugger's address space.
    DetourSetCodeModule(GetModuleHandleW(nullptr), TRUE);
    for (size_t cursor = 0; cursor < count;)
    {
        auto next = static_cast<BYTE*>(DetourCopyInstruction(nullptr, nullptr,
            bytes.data() + cursor, nullptr, nullptr));
        auto length = next ? static_cast<size_t>(next - bytes.data() - cursor) : 0;
        if (!length || length > count - cursor) break;
        if (bytes[cursor] == 0xC3 || bytes[cursor] == 0xC2 ||
            (length == 2 && bytes[cursor] == 0xF3 && bytes[cursor + 1] == 0xC3))
        {
            ComPtr<ICorDebugFunctionBreakpoint> breakpoint;
            DebuggerReadCache::Invalidate();
            if (SUCCEEDED(code->CreateBreakpoint(static_cast<ULONG32>(cursor), &breakpoint)) &&
                SUCCEEDED(breakpoint->Activate(TRUE)))
            {
                points_.emplace(breakpoint.Get(), DebugStopPoint{method, true, breakpoint, address + cursor});
                created_.push_back(breakpoint.Get());
            }
            DebuggerReadCache::Invalidate();
        }
        cursor += length;
    }
    nativeCode_.insert(address);
}

void RuntimeDebugger::Snapshot(uint32_t parameter, ValueKind kind, const void* data, uint64_t size, bool readable,
    uint32_t stride)
{
    const auto capacity = transport_.Header()->payloadCapacity;
    if (payload_.size() + sizeof(Value) > capacity) return;
    auto count = static_cast<uint32_t>(std::min<uint64_t>(size, limit_));
    count = std::min(count, capacity - static_cast<uint32_t>(payload_.size()) - static_cast<uint32_t>(sizeof(Value)));
    Value value{parameter, kind, count < size ? Truncated : 0u, readable ? count : 0u, size};
    if (kind == ValueKind::ManagedArray)
        value.originalBytes = (uint64_t{stride} << 32) | (stride ? size / stride : 0);
    if (!readable) value.flags |= Unreadable;
    auto offset = payload_.size();
    payload_.resize(offset + sizeof(value) + value.capturedBytes);
    memcpy(payload_.data() + offset, &value, sizeof(value));
    if (value.capturedBytes) memcpy(payload_.data() + offset + sizeof(value), data, value.capturedBytes);
}

void RuntimeDebugger::ReadValue(uint32_t parameter, ICorDebugValue* value, uint64_t& scalar, uint32_t depth)
{
    if (!value || depth > 8) { Snapshot(parameter, ValueKind::Bytes, nullptr, 0, false); return; }
    ComPtr<ICorDebugReferenceValue> reference;
    if (SUCCEEDED(value->QueryInterface(__uuidof(ICorDebugReferenceValue),
        reinterpret_cast<void**>(reference.GetAddressOf()))))
    {
        CORDB_ADDRESS address = 0;
        auto result = reference->GetValue(&address);
        if (!depth) scalar = address;
        if (!depth) Snapshot(parameter, ValueKind::Scalar, &address, sizeof(void*), SUCCEEDED(result));
        if (FAILED(result) || !address) return;
        ComPtr<ICorDebugValue> indirect;
        if (FAILED(reference->Dereference(&indirect))) Snapshot(parameter, ValueKind::Bytes, nullptr, 0, false);
        else ReadValue(parameter, indirect.Get(), scalar, depth + 1);
        return;
    }
    ComPtr<ICorDebugStringValue> string;
    if (SUCCEEDED(value->QueryInterface(__uuidof(ICorDebugStringValue),
        reinterpret_cast<void**>(string.GetAddressOf()))))
    {
        ULONG32 size = 0, copied = 0;
        auto result = string->GetLength(&size);
        std::vector<wchar_t> characters(std::min<size_t>(size, limit_ / sizeof(wchar_t)) + 1, 0);
        if (SUCCEEDED(result)) result = string->GetString(static_cast<ULONG32>(characters.size()), &copied,
            characters.data());
        Snapshot(parameter, ValueKind::Utf16, characters.data(), static_cast<uint64_t>(size) * sizeof(wchar_t),
            SUCCEEDED(result));
        return;
    }
    ComPtr<ICorDebugArrayValue> array;
    if (SUCCEEDED(value->QueryInterface(__uuidof(ICorDebugArrayValue),
        reinterpret_cast<void**>(array.GetAddressOf()))))
    {
        ULONG32 count = 0, size = 0;
        CORDB_ADDRESS address = 0;
        ComPtr<ICorDebugValue> element;
        auto result = array->GetCount(&count);
        if (SUCCEEDED(result) && count) result = array->GetElementAtPosition(0, &element);
        if (element && SUCCEEDED(result)) result = element->GetSize(&size);
        if (element && SUCCEEDED(result)) result = element->GetAddress(&address);

        // Empty arrays still have a runtime element stride, even though no element can be inspected.
        if (SUCCEEDED(result) && !count && SUCCEEDED(result = array->GetAddress(&address)))
        {
            if (legacy_)
            {
                // The legacy array method table stores the component size in its first word.
                CORDB_ADDRESS table = 0;
                WORD stride = 0;
                SIZE_T copied = 0;
                result = process_->ReadMemory(address, sizeof(table), reinterpret_cast<BYTE*>(&table), &copied);
                if (SUCCEEDED(result) && copied == sizeof(table))
                    result = process_->ReadMemory(table, sizeof(stride), reinterpret_cast<BYTE*>(&stride), &copied);
                if (SUCCEEDED(result) && copied == sizeof(stride) && stride) size = stride;
                else result = E_FAIL;
            }
            else
            {
                ComPtr<ICorDebugProcess5> heap;
                COR_TYPEID type{};
                COR_ARRAY_LAYOUT layout{};
                result = process_.As(&heap);
                if (SUCCEEDED(result)) result = heap->GetTypeID(address, &type);
                if (SUCCEEDED(result)) result = heap->GetArrayLayout(type, &layout);
                if (SUCCEEDED(result)) size = layout.elementSize;
            }
        }
        auto original = static_cast<uint64_t>(count) * size;
        scratch_.resize(static_cast<size_t>(std::min<uint64_t>(original, limit_)));
        SIZE_T read = 0;
        if (address && !scratch_.empty() && SUCCEEDED(result))
            result = process_->ReadMemory(address, static_cast<DWORD>(scratch_.size()),
                reinterpret_cast<BYTE*>(scratch_.data()), &read);
        Snapshot(parameter, ValueKind::ManagedArray, scratch_.data(), original,
            SUCCEEDED(result) && read == scratch_.size(), size);
        return;
    }

    // Read register-backed primitives and bounded structure data without allocating their full original size.
    ULONG32 size = 0;
    CORDB_ADDRESS address = 0;
    auto result = value->GetSize(&size);
    scratch_.resize(std::min(size, limit_));
    ComPtr<ICorDebugGenericValue> generic;
    if (size <= sizeof(uint64_t) && SUCCEEDED(value->QueryInterface(__uuidof(ICorDebugGenericValue),
        reinterpret_cast<void**>(generic.GetAddressOf()))))
    {
        uint64_t number = 0;
        result = generic->GetValue(&number);
        if (!depth) scalar = number;
        Snapshot(parameter, depth ? ValueKind::Bytes : ValueKind::Scalar, &number, size, SUCCEEDED(result));
        return;
    }
    SIZE_T read = 0;
    if (SUCCEEDED(result)) result = value->GetAddress(&address);
    if (address && SUCCEEDED(result)) result = process_->ReadMemory(address, static_cast<DWORD>(scratch_.size()),
        reinterpret_cast<BYTE*>(scratch_.data()), &read);
    Snapshot(parameter, ValueKind::Bytes, scratch_.data(), size, SUCCEEDED(result) && read == scratch_.size());
}

void RuntimeDebugger::Publish(Event event, const std::vector<std::byte>& payload)
{
    if (auto slot = transport_.Acquire())
    {
        event.payloadBytes = static_cast<uint32_t>(payload.size());
        slot->event = event;
        if (!payload.empty()) memcpy(Transport::Payload(slot), payload.data(), payload.size());
        transport_.Publish(slot);
    }
}

void RuntimeDebugger::PublishMetadata(DebugMethod& method)
{
    if (method.published) return;
    DynamicApiMetadata metadata{};
    metadata.argumentCount = static_cast<uint32_t>(
        std::min<size_t>(method.metadata.arguments.size(), MaximumArguments));
    metadata.category = method.category;
    auto module = Utf8(method.metadata.moduleName), name = Utf8(method.metadata.name);
    strncpy_s(metadata.module, module.c_str(), _TRUNCATE);
    strncpy_s(metadata.name, name.c_str(), _TRUNCATE);
    wcsncpy_s(metadata.parameters, method.metadata.parameters.c_str(), _TRUNCATE);
    Event event{};
    event.kind = EventKind::ApiMetadata;
    event.api = static_cast<Api>(method.metadata.api);
    event.processId = transport_.Header()->processId;
    event.timestamp = Clock();
    std::vector<std::byte> payload(sizeof(metadata));
    memcpy(payload.data(), &metadata, sizeof(metadata));
    Publish(event, payload);
    method.published = true;
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&transport_.Header()->managedApiCount));
}

void RuntimeDebugger::CaptureStack(ICorDebugThread* thread)
{
    if (!transport_.Header()->stackDepth) return;
    std::array<uint64_t, MaximumStack> addresses{};
    uint32_t count = 0;
    ComPtr<ICorDebugChain> chain;
    thread->GetActiveChain(&chain);
    while (chain && count < std::min(transport_.Header()->stackDepth, MaximumStack))
    {
        ComPtr<ICorDebugFrame> frame;
        chain->GetActiveFrame(&frame);
        while (frame && count < std::min(transport_.Header()->stackDepth, MaximumStack))
        {
            ComPtr<ICorDebugNativeFrame> native;
            ComPtr<ICorDebugCode> code;
            CORDB_ADDRESS address = 0;
            ULONG32 offset = 0;
            if (SUCCEEDED(frame.As(&native)) && SUCCEEDED(native->GetCode(&code)) && code &&
                SUCCEEDED(code->GetAddress(&address)) && SUCCEEDED(native->GetIP(&offset)))
                addresses[count++] = address + offset;
            ComPtr<ICorDebugFrame> caller;
            frame->GetCaller(&caller);
            frame = caller;
        }
        ComPtr<ICorDebugChain> caller;
        chain->GetCaller(&caller);
        chain = caller;
    }
    auto savedLimit = limit_;
    limit_ = MaximumStack * sizeof(uint64_t);
    Snapshot(UINT32_MAX, ValueKind::Stack, addresses.data(), count * sizeof(uint64_t));
    limit_ = savedLimit;
}

bool RuntimeDebugger::ReadHeapValue(uint32_t parameter, uint64_t address)
{
    if (!address)
    {
        Snapshot(parameter, ValueKind::Scalar, &address, sizeof(void*));
        return true;
    }
    ComPtr<ICorDebugProcess5> heap;
    if (FAILED(process_.As(&heap))) return false;
    COR_TYPEID type{};
    COR_ARRAY_LAYOUT array{};
    COR_TYPE_LAYOUT layout{};
    if (SUCCEEDED(heap->GetTypeID(address, &type)) && SUCCEEDED(heap->GetTypeLayout(type, &layout)) &&
        SUCCEEDED(heap->GetArrayLayout(type, &array)))
    {
        // The runtime supplies the layout of both strings and arrays.
        ULONG32 count = 0;
        SIZE_T read = 0;
        if (FAILED(process_->ReadMemory(address + array.countOffset, sizeof(count),
            reinterpret_cast<BYTE*>(&count), &read)) || read != sizeof(count)) return false;
        auto original = static_cast<uint64_t>(count) * array.elementSize;
        scratch_.resize(static_cast<size_t>(std::min<uint64_t>(original, limit_)));
        read = 0;
        auto result = scratch_.empty() ? S_OK : process_->ReadMemory(address + array.firstElementOffset,
            static_cast<DWORD>(scratch_.size()), reinterpret_cast<BYTE*>(scratch_.data()), &read);
        Snapshot(parameter, ValueKind::Scalar, &address, sizeof(void*));
        Snapshot(parameter, layout.type == ELEMENT_TYPE_STRING ? ValueKind::Utf16 : ValueKind::ManagedArray,
            scratch_.data(), original, SUCCEEDED(result) && read == scratch_.size(), array.elementSize);
        return true;
    }
    ComPtr<ICorDebugObjectValue> object;
    if (FAILED(heap->GetObject(address, &object))) return false;
    Snapshot(parameter, ValueKind::Scalar, &address, sizeof(void*));
    uint64_t scalar = 0;
    ReadValue(parameter, object.Get(), scalar, 1);
    return true;
}

void RuntimeDebugger::ReadEntryArgument(uint32_t index, ICorDebugThread* thread,
    ComPtr<ICorDebugNativeFrame>& frame, const CONTEXT& context, DebugInvocation& call,
    ComPtr<ICorDebugHeapValue2>& root)
{
    const auto& type = call.method->metadata.arguments[index];
        uint64_t scalar = 0;
    SIZE_T read = 0;
    uint64_t slot = 0;
    int argumentRegister = -1;
#ifdef _WIN64
    const auto position = index + (call.hiddenContext && (!call.method->instance || index) ? 1 : 0);
    const uint64_t registers[] = {context.Rcx, context.Rdx, context.R8, context.R9};
    const M128A floating[] = {context.Xmm0, context.Xmm1, context.Xmm2, context.Xmm3};
    const CorDebugRegister argumentRegisters[] =
        {REGISTER_AMD64_RCX, REGISTER_AMD64_RDX, REGISTER_AMD64_R8, REGISTER_AMD64_R9};
    slot = ContextSp(context) + sizeof(void*) * (position + 1);
    const auto slotBytes = sizeof(scalar);
    if (position < std::size(registers))
    {
        scalar = !type.byReference && (type.element == ELEMENT_TYPE_R4 || type.element == ELEMENT_TYPE_R8) ?
            floating[position].Low : registers[position];
        argumentRegister = argumentRegisters[position];
    }
#else
    // CLR x86 assigns eligible arguments to ECX/EDX and pushes the remaining values from left to right.
    const uint32_t registers[] = {context.Ecx, context.Edx};
    const CorDebugRegister argumentRegisters[] = {REGISTER_X86_ECX, REGISTER_X86_EDX};
    size_t registerCount = 0;
    uint32_t followingBytes = 0;
    bool onStack = false;
    for (size_t parameter = 0; parameter < call.method->metadata.arguments.size(); ++parameter)
    {
        const auto& value = call.method->metadata.arguments[parameter];
        auto eligible = value.byReference || (value.bytes <= sizeof(void*) &&
            value.element != ELEMENT_TYPE_R4 && value.element != ELEMENT_TYPE_R8 &&
            value.element != ELEMENT_TYPE_VALUETYPE && value.element != ELEMENT_TYPE_GENERICINST);
        if (eligible && registerCount < std::size(registers))
        {
            if (parameter == index)
            {
                scalar = registers[registerCount];
                argumentRegister = argumentRegisters[registerCount];
            }
            ++registerCount;
        }
        else if (parameter == index) onStack = true;
        else if (parameter > index) followingBytes += (value.bytes + 3) & ~3u;
    }
    if (call.hiddenContext && (onStack || registerCount == std::size(registers)))
        followingBytes += sizeof(void*);
    slot = ContextSp(context) + sizeof(void*) + followingBytes;
    const auto slotBytes = type.byReference ? sizeof(void*) : std::min<size_t>(type.bytes, sizeof(scalar));
#endif
    if (argumentRegister < 0 && (FAILED(process_->ReadMemory(slot, static_cast<DWORD>(slotBytes),
        reinterpret_cast<BYTE*>(&scalar), &read)) || read != slotBytes))
    {
        Snapshot(index, ValueKind::Bytes, nullptr, type.bytes, false);
        return;
    }
    call.event.arguments[index] = scalar;
    if (type.byReference)
    {
        auto& output = call.outputs[index];
        output.address = scalar;
        output.element = type.element;
        output.bytes = type.referencedBytes;
        Snapshot(index, ValueKind::Scalar, &scalar, sizeof(void*));
    }
    bool reference = IsManagedReference(type.element) || type.element == ELEMENT_TYPE_GENERICINST;
    if (!reference)
    {
        auto bytes = type.byReference ? type.referencedBytes : type.bytes;
        if (type.byReference)
        {
            scratch_.resize(std::min(bytes, limit_));
            auto result = process_->ReadMemory(scalar, static_cast<DWORD>(scratch_.size()),
                reinterpret_cast<BYTE*>(scratch_.data()), &read);
            Snapshot(index, ValueKind::Bytes, scratch_.data(), bytes,
                bytes && SUCCEEDED(result) && read == scratch_.size());
        }
        else
        {
            if (bytes < sizeof(scalar)) scalar &= UINT64_MAX >> (64 - bytes * 8);
            call.event.arguments[index] = scalar;
            Snapshot(index, ValueKind::Scalar, &scalar, bytes);
        }
        return;
    }
    auto address = scalar;
    if (type.byReference && (FAILED(process_->ReadMemory(scalar, sizeof(void*),
        reinterpret_cast<BYTE*>(&address), &read)) || read != sizeof(void*)))
    {
        Snapshot(index, ValueKind::Bytes, nullptr, 0, false);
        return;
    }

    // Modern runtimes expose heap values without walking a managed frame.
    auto captured = ReadHeapValue(index, address);
    auto needsRoot = !type.byReference && address && type.arrayRank;
    if (captured && !needsRoot) return;

    // Construct roots from a frame-associated value so the runtime receives the owning application domain.
    if (!frame)
    {
        ComPtr<ICorDebugFrame> active;
        thread->GetActiveFrame(&active);
        if (active) active.As(&frame);
    }
    ComPtr<ICorDebugValue> value;
    ComPtr<ICorDebugCode> code;
    CORDB_ADDRESS frameAddress = 0;
    if (frame && SUCCEEDED(frame->GetCode(&code)) && code &&
        SUCCEEDED(code->GetAddress(&frameAddress)) && frameAddress == call.nativeEntry)
    {
        BYTE signature = ELEMENT_TYPE_OBJECT;
        if (type.byReference || argumentRegister < 0)
            frame->GetLocalMemoryValue(type.byReference ? scalar : slot, sizeof(signature), &signature, &value);
        else
            frame->GetLocalRegisterValue(
                static_cast<CorDebugRegister>(argumentRegister), sizeof(signature), &signature, &value);
    }
    uint64_t ignored = 0;
    if (!captured) ReadValue(index, value.Get(), ignored, type.byReference ? 1 : 0);
    if (needsRoot && value)
    {
        ComPtr<ICorDebugReferenceValue> referenceValue;
        ComPtr<ICorDebugValue> object;
        if (SUCCEEDED(value.As(&referenceValue)) && SUCCEEDED(referenceValue->Dereference(&object)) && object)
            object.As(&root);
    }
}

void RuntimeDebugger::Enter(DebugMethod* method, ICorDebugThread* thread, ICorDebugFrame* frame,
    const CONTEXT& context, CORDB_ADDRESS nativeEntry, ULONG32 nativeBytes)
{
    DWORD threadId = 0;
    thread->GetID(&threadId);
    auto& calls = threads_[threadId];
    payload_.clear();
    CORDB_ADDRESS returnAddress = 0;
    SIZE_T read = 0;
    if (nativeEntry) process_->ReadMemory(ContextSp(context), sizeof(void*),
        reinterpret_cast<BYTE*>(&returnAddress), &read);
    if (read != sizeof(void*)) returnAddress = 0;
    while (!calls.empty() && ContextSp(context) >= calls.back().stack)
    {
        if (ContextSp(context) == calls.back().stack && returnAddress && calls.back().returnAddress == returnAddress)
            break;
        EndTop(threadId, Failed | Unwound);
    }
    calls.emplace_back();
    auto& call = calls.back();
    call.method = method;
    call.stack = ContextSp(context);
    call.nativeEntry = nativeEntry;
    call.nativeBytes = nativeBytes;
    call.returnAddress = returnAddress;
    call.resultElement = method->metadata.result.element;
    call.resultBytes = method->metadata.result.bytes;
    auto header = transport_.Header();
    if (closing_ || header->stop || header->capturePaused || !FilterEnabled(header->enabledFilters,
        ManagedApis, CategoryMask(method->category))) return;
    PublishMetadata(*method);
    call.event.kind = EventKind::Enter;
    call.event.api = static_cast<Api>(method->metadata.api);
    call.event.processId = header->processId;
    call.event.threadId = threadId;
    call.event.callId = InterlockedIncrement64(&header->nextCallId);
    call.event.timestamp = Clock();
    call.event.depth = static_cast<uint32_t>(calls.size() - 1);
    if (calls.size() > 1) call.event.parentId = calls[calls.size() - 2].event.callId;
    InterlockedIncrement64(&header->recordingCalls);
    limit_ = header->bufferLimit;

    // Resolve return parameters and the shared-code context argument from this invocation's instantiation.
    bool entryValuesKnown = nativeEntry && method->entryAbiKnown;
    if (method->classParameters || method->methodParameters)
    {
        ComPtr<ICorDebugILFrame2> genericFrame;
        ComPtr<ICorDebugTypeEnum> parameters;
        ComPtr<ICorDebugType> type;
        ULONG fetched = 0;
        if (frame && SUCCEEDED(frame->QueryInterface(__uuidof(ICorDebugILFrame2),
            reinterpret_cast<void**>(genericFrame.GetAddressOf()))) &&
            SUCCEEDED(genericFrame->EnumerateTypeParameters(&parameters)))
        {
            ULONG32 parameter = 0;
            while (SUCCEEDED(parameters->Next(1, &type, &fetched)) && fetched == 1)
            {
                CorElementType element = ELEMENT_TYPE_END;
                if (FAILED(type->GetType(&element))) { entryValuesKnown = false; break; }
                if (parameter == method->resultTypeIndex) call.resultElement = element;
                auto contextParameter = parameter < method->classParameters ? !method->instance : true;
                if (contextParameter && IsManagedReference(element)) call.hiddenContext = true;
                ++parameter;
                type.Reset();
            }
            if (parameter != method->classParameters + method->methodParameters) entryValuesKnown = false;
            call.resultBytes = IsManagedReference(call.resultElement) ? sizeof(void*) :
                ManagedScalarBytes(call.resultElement);
        }
        else entryValuesKnown = false;
    }
    if (call.resultElement != ELEMENT_TYPE_VOID && !call.resultBytes) entryValuesKnown = false;
    ComPtr<ICorDebugILFrame> il;
    if (frame) frame->QueryInterface(__uuidof(ICorDebugILFrame),
        reinterpret_cast<void**>(il.GetAddressOf()));
    ComPtr<ICorDebugNativeFrame> entryFrame;
    if (frame) frame->QueryInterface(__uuidof(ICorDebugNativeFrame),
        reinterpret_cast<void**>(entryFrame.GetAddressOf()));
    std::array<ComPtr<ICorDebugHeapValue2>, MaximumArguments> roots;
    for (uint32_t index = 0; index < std::min<size_t>(method->metadata.arguments.size(), MaximumArguments); ++index)
    {
        if (entryValuesKnown)
        {
            ReadEntryArgument(index, thread, entryFrame, context, call, roots[index]);
            continue;
        }
        ComPtr<ICorDebugValue> value;
        if (!il || FAILED(il->GetArgument(index, &value)))
        {
            Snapshot(index, ValueKind::Bytes, nullptr, method->metadata.arguments[index].bytes, false);
            continue;
        }
        ReadValue(index, value.Get(), call.event.arguments[index]);
        const auto& type = method->metadata.arguments[index];
        ComPtr<ICorDebugReferenceValue> reference;
        if (FAILED(value.As(&reference))) continue;
        if (type.byReference)
        {
            auto& output = call.outputs[index];
            reference->GetValue(&output.address);
            ComPtr<ICorDebugValue> referent;
            if (SUCCEEDED(reference->Dereference(&referent)) && referent)
            {
                referent->GetType(&output.element);
                referent->GetSize(&output.bytes);
            }
        }
        else if (type.arrayRank)
        {
            ComPtr<ICorDebugValue> object;
            if (SUCCEEDED(reference->Dereference(&object)) && object) object.As(&roots[index]);
        }
    }
    CaptureStack(thread);

    // Each handle request changes the runtime's shared debugger reply and handle storage.
    for (uint32_t index = 0; index < MaximumArguments; ++index)
        if (roots[index])
        {
            DebuggerReadCache::Invalidate();
            roots[index]->CreateHandle(HANDLE_STRONG, &call.outputs[index].root);
            DebuggerReadCache::Invalidate();
        }
    Hold(call.event, false);
    Publish(call.event, payload_);
}

void RuntimeDebugger::EndTop(DWORD threadId, uint32_t flags)
{
    auto& calls = threads_[threadId];
    if (calls.empty()) return;
    auto& call = calls.back();
    for (auto& output : call.outputs)
        if (output.root)
        {
            DebuggerReadCache::Invalidate();
            output.root->Dispose();
            DebuggerReadCache::Invalidate();
        }
    if (call.event.callId)
    {
        call.event.kind = EventKind::Leave;
        call.event.timestamp = Clock();
        call.event.flags |= flags;
        Publish(call.event, payload_);
        InterlockedDecrement64(&transport_.Header()->recordingCalls);
    }
    calls.pop_back();
}

void RuntimeDebugger::Leave(DebugMethod* method, DWORD threadId, ICorDebugThread* thread, ICorDebugNativeFrame* frame,
    const CONTEXT& context)
{
    auto& calls = threads_[threadId];
    for (;;)
    {
        auto index = calls.size();
        while (index && calls[index - 1].method != method) --index;
        if (!index) return;
        payload_.clear();
        while (calls.size() > index) EndTop(threadId, Failed | Unwound);
        auto& call = calls.back();
        if (call.event.callId)
        {
            limit_ = transport_.Header()->bufferLimit;
            ComPtr<ICorDebugNativeFrame> native = frame;
            auto resolveFrame = [&]()
            {
                if (native) return true;
                ComPtr<ICorDebugFrame> active;
                return SUCCEEDED(thread->GetActiveFrame(&active)) && active && SUCCEEDED(active.As(&native));
            };

            // Read tracked outputs directly; a native frame is needed only when heap inspection is unavailable.
            for (uint32_t parameter = 0; parameter < MaximumArguments; ++parameter)
            {
                auto& output = call.outputs[parameter];
                ComPtr<ICorDebugValue> value;
                if (output.root)
                {
                    CORDB_ADDRESS address = 0;
                    if (!legacy_ && SUCCEEDED(output.root->GetValue(&address)) &&
                        ReadHeapValue(parameter, address)) continue;
                    output.root->Dereference(&value);
                }
                else if (output.address)
                {
                    auto element = output.element;
                    if (IsManagedReference(element))
                    {
                        uintptr_t address = 0;
                        SIZE_T read = 0;
                        if (SUCCEEDED(process_->ReadMemory(output.address, sizeof(address),
                            reinterpret_cast<BYTE*>(&address), &read)) && read == sizeof(address) &&
                            ReadHeapValue(parameter, address)) continue;
                        BYTE signature = ELEMENT_TYPE_OBJECT;
                        if (resolveFrame()) native->GetLocalMemoryValue(output.address, sizeof(signature), &signature,
                            &value);
                    }
                    else
                    {
                        scratch_.resize(std::min(output.bytes, limit_));
                        SIZE_T read = 0;
                        auto result = process_->ReadMemory(output.address, static_cast<DWORD>(scratch_.size()),
                            reinterpret_cast<BYTE*>(scratch_.data()), &read);
                        Snapshot(parameter, ValueKind::Bytes, scratch_.data(), output.bytes,
                            SUCCEEDED(result) && read == scratch_.size());
                        continue;
                    }
                }
                if (output.root || output.address)
                {
                    uint64_t scalar = 0;
                    ReadValue(parameter, value.Get(), scalar, output.address ? 1 : 0);
                }
            }
            if (!method->resultSignature.empty() && call.resultElement != ELEMENT_TYPE_VOID)
            {
                const auto& type = method->metadata.result;
                const auto element = call.resultElement;
                const auto bytes = call.resultBytes;
                bool captured = false;
                const bool heapResult = IsManagedReference(element) || element == ELEMENT_TYPE_GENERICINST;
                const bool reference = heapResult && (element != ELEMENT_TYPE_GENERICINST || bytes == sizeof(void*));
                if (!type.byReference && bytes && bytes <= sizeof(uint64_t))
                {
                    // Return registers are already in the stopped frame's context.
                    auto scalar = ContextResult(context, element);
                    if (ManagedScalarBytes(element))
                    {
                        if (bytes < sizeof(scalar)) scalar &= UINT64_MAX >> (64 - bytes * 8);
                        call.event.result = scalar;
                        Snapshot(UINT32_MAX, ValueKind::Scalar, &scalar, bytes);
                        captured = true;
                    }
                    else if (heapResult && ReadHeapValue(UINT32_MAX, scalar))
                    {
                        call.event.result = scalar;
                        captured = true;
                    }
                }
                if (!captured)
                {
                    ComPtr<ICorDebugValue> value;
#ifdef _WIN64
                    auto reg = element == ELEMENT_TYPE_R4 || element == ELEMENT_TYPE_R8 ?
                        REGISTER_AMD64_XMM0 : REGISTER_AMD64_RAX;
#else
                    auto reg = REGISTER_X86_EAX;
#endif
                    if (reference && !type.byReference)
                    {
                        // Native register values have no generic context; dereference the runtime object instead.
                        BYTE signature = ELEMENT_TYPE_OBJECT;
                        if (resolveFrame()) native->GetLocalRegisterValue(reg, sizeof(signature), &signature, &value);
                    }
                    else if (method->resultTypeIndex == UINT32_MAX && type.element != ELEMENT_TYPE_GENERICINST &&
                        type.name.find(L'!') == std::wstring::npos && resolveFrame())
                        native->GetLocalRegisterValue(reg, static_cast<ULONG>(method->resultSignature.size()),
                            method->resultSignature.data(), &value);
                    ReadValue(UINT32_MAX, value.Get(), call.event.result);
                    if (!value) call.event.result = ContextResult(context, element);
                }
            }
            Hold(call.event, true);
        }
        auto stack = call.stack;
        auto returnAddress = call.returnAddress;
        EndTop(threadId, 0);

        // Tail-call wrappers share their caller's return address and complete with the final callee's result.
        if (!returnAddress || calls.empty() || calls.back().stack != stack ||
            calls.back().returnAddress != returnAddress) return;
        method = calls.back().method;
    }
}

HRESULT RuntimeDebugger::Breakpoint(ICorDebugAppDomain* domain, ICorDebugThread* thread,
    ICorDebugBreakpoint* breakpoint)
{
    std::unique_lock lock(callbacks_);
    try
    {
        auto point = points_.find(breakpoint);
        if (!closing_ && point != points_.end())
        {
            DebuggerReadCache cache(transport_.Header()->processId);
            auto method = point->second.method;
            auto leaving = point->second.leaving;
            DWORD threadId = 0;
            thread->GetID(&threadId);
            auto header = transport_.Header();
            auto active = threads_.find(threadId);
            auto selected = !header->stop && !header->capturePaused &&
                FilterEnabled(header->enabledFilters, ManagedApis, CategoryMask(method->category));
            auto breakpoints = ((header->entryBreaks | header->exitBreaks) & ManagedApis) ||
                header->entryApi == static_cast<LONG>(method->metadata.api) ||
                header->exitApi == static_cast<LONG>(method->metadata.api);

            // Disabled methods need no stopped-frame inspection unless an earlier invocation must complete.
            if (!selected && !breakpoints && (active == threads_.end() || active->second.empty()))
            {
                lock.unlock();
                return domain->Continue(FALSE);
            }
            CONTEXT context{};
            context.ContextFlags = CONTEXT_ALL;
            auto readContext = SUCCEEDED(process_->GetThreadContext(threadId, sizeof(context),
                reinterpret_cast<BYTE*>(&context))) && ContextSp(context) >= 65536;
            ComPtr<ICorDebugThread3> modern;
            ComPtr<ICorDebugStackWalk> walk;
            if (!readContext || (point->second.address && !AtBreakpointAddress(context, point->second.address)))
            {
                // The stack-walk context is available before requesting any frame inspection.
                ULONG32 bytes = 0;
                if (SUCCEEDED(thread->QueryInterface(__uuidof(ICorDebugThread3),
                    reinterpret_cast<void**>(modern.GetAddressOf()))) &&
                    SUCCEEDED(modern->CreateStackWalk(&walk)))
                    readContext = SUCCEEDED(walk->GetContext(CONTEXT_ALL, sizeof(context), &bytes,
                        reinterpret_cast<BYTE*>(&context))) && ContextSp(context) >= 65536;
            }
            auto& calls = threads_[threadId];

            // An IL entry in a body already captured at native entry must not create a duplicate invocation.
            auto duplicateEntry = [&]()
            {
                return !leaving && !point->second.entryCode && !calls.empty() && calls.back().method == method &&
                    calls.back().nativeEntry && ContextSp(context) <= calls.back().stack &&
                    ContextIp(context) >= calls.back().nativeEntry &&
                    ContextIp(context) - calls.back().nativeEntry < calls.back().nativeBytes;
            };

            // Returns usually need only the stopped register context and previously tracked output locations.
            if (readContext && point->second.entryCode && AtBreakpointAddress(context, point->second.address))
            {
                ComPtr<ICorDebugFrame> frame;
                if (method->classParameters || method->methodParameters)
                {
                    if (walk) walk->GetFrame(&frame);
                    else thread->GetActiveFrame(&frame);
                }
                Enter(method, thread, frame.Get(), context, point->second.address, point->second.codeBytes);
            }
            else if (leaving && readContext && AtBreakpointAddress(context, point->second.address))
            {
                Leave(method, threadId, thread, nullptr, context);
            }
            else if (!readContext || !duplicateEntry())
            {
                ComPtr<ICorDebugFrame> frame;
                ComPtr<ICorDebugNativeFrame> native;
                ComPtr<ICorDebugRegisterSet> registers;

                // Read the leaf frame directly when the runtime supports it; legacy runtimes expose an active frame.
                ULONG32 contextBytes = 0;
                auto result = walk ? S_OK : thread->QueryInterface(__uuidof(ICorDebugThread3),
                    reinterpret_cast<void**>(modern.GetAddressOf()));
                if (SUCCEEDED(result) && !walk) result = modern->CreateStackWalk(&walk);
                if (SUCCEEDED(result)) result = walk->GetFrame(&frame);
                if (SUCCEEDED(result) && frame) result = walk->GetContext(CONTEXT_ALL, sizeof(context), &contextBytes,
                    reinterpret_cast<BYTE*>(&context));
                if (FAILED(result) || !frame)
                {
                    frame.Reset();
                    result = thread->GetActiveFrame(&frame);
                    if (SUCCEEDED(result) && frame) result = frame.As(&native);
                    if (SUCCEEDED(result) && native) result = native->GetRegisterSet(&registers);
                    if (SUCCEEDED(result) && registers) result = registers->GetThreadContext(sizeof(context),
                        reinterpret_cast<BYTE*>(&context));
                }
                if (SUCCEEDED(result) && frame && SUCCEEDED(frame.As(&native)))
                {
                    if (leaving) Leave(method, threadId, thread, native.Get(), context);
                    else if (!duplicateEntry())
                    {
                        ComPtr<ICorDebugCode> code;
                        if (SUCCEEDED(native->GetCode(&code)) && method->armed) InstallNativeCode(method, code.Get());
                        CORDB_ADDRESS address = 0;
                        ULONG32 size = 0;
                        auto knownCode = code && SUCCEEDED(code->GetAddress(&address)) &&
                            SUCCEEDED(code->GetSize(&size));
                        if (knownCode && AtBreakpointAddress(context, address))
                            Enter(method, thread, frame.Get(), context, address, size);
                        else
                        {
                            CONTEXT entry{};
                            if (legacy_ && knownCode && method->entryAbiKnown &&
                                RecoverEntryContext(native.Get(), code.Get(), context, entry))
                                Enter(method, thread, frame.Get(), entry, address, size);
                            else Enter(method, thread, frame.Get(), context);
                        }
                    }
                }
            }
        }
    }
    catch (...) { transport_.Header()->managedState = static_cast<LONG>(ManagedState::Failed); }
    return domain->Continue(FALSE);
}

HRESULT RuntimeDebugger::ExitThread(ICorDebugAppDomain* domain, ICorDebugThread* thread)
{
    std::lock_guard lock(callbacks_);
    DWORD threadId = 0;
    thread->GetID(&threadId);
    payload_.clear();
    while (!threads_[threadId].empty()) EndTop(threadId, Unwound);
    threads_.erase(threadId);
    return domain->Continue(FALSE);
}

bool RuntimeDebugger::WaitForResume()
{
    held_ = true;
    while (!closing_ && !transport_.Header()->stop && transport_.CollectorAlive())
        if (WaitForSingleObject(transport_.ResumeEvent(), 100) == WAIT_OBJECT_0) { held_ = false; return true; }
    held_ = false;
    return false;
}

void RuntimeDebugger::Hold(Event& event, bool leaving)
{
    auto header = transport_.Header();
    auto mask = leaving ? header->exitBreaks : header->entryBreaks;
    auto exact = leaving ? header->exitApi : header->entryApi;
    if (header->stop || (!(mask & ManagedApis) && exact != static_cast<LONG>(event.api))) return;
    auto& breakpoint = header->breakpoint;
    if (InterlockedCompareExchange(&breakpoint.ownerThread, static_cast<LONG>(event.threadId), 0)) return;
    ResetEvent(transport_.ResumeEvent());
    breakpoint.event = event;
    breakpoint.phase = static_cast<LONG>(leaving ? BreakpointPhase::Leave : BreakpointPhase::Enter);
    breakpoint.action = static_cast<LONG>(BreakpointAction::Continue);
    breakpoint.waiting = 1;
    SetEvent(transport_.BreakEvent());
    WaitForResume();
    breakpoint.waiting = 0;
    InterlockedExchange(&breakpoint.ownerThread, 0);
}

HRESULT RuntimeDebugger::Shutdown()
{
    if (closing_.exchange(true)) return shutdownResult_;
    held_ = false;
    SetEvent(transport_.ResumeEvent());
    if (process_ && !exited_)
    {
        auto result = process_->Stop(5000);
        if (SUCCEEDED(result))
        {
            // End open calls before removing breakpoints so the agent can finish stopping meanwhile.
            std::lock_guard lock(callbacks_);
            for (auto& [thread, calls] : threads_)
            {
                payload_.clear();
                while (!calls.empty()) EndTop(thread, Unwound);
            }

            // Remove newest breakpoints first; the runtime unlinks each from its newest-first controller list.
            for (auto breakpoint = created_.rbegin(); breakpoint != created_.rend(); ++breakpoint)
            {
                BOOL active = FALSE;
                if (SUCCEEDED((*breakpoint)->IsActive(&active)) && active) (*breakpoint)->Activate(FALSE);
            }
            result = process_->Detach();
        }
        shutdownResult_ = result;
    }
    if (debugger_) debugger_->Terminate();
    points_.clear();
    created_.clear();
    threads_.clear();
    process_.Reset();
    debugger_.Reset();
    return shutdownResult_;
}

std::unique_ptr<ManagedDebugger> AttachManagedDebugger(DWORD processId, Transport& transport,
    const std::wstring& runtime, bool legacy, HRESULT& result)
{
    auto debugger = std::make_unique<RuntimeDebugger>(transport);
    result = debugger->Initialize(processId, runtime, legacy);
    return SUCCEEDED(result) ? std::move(debugger) : nullptr;
}
}
