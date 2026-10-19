#include "ManagedMetadata.h"
#include "ProfilerCallbacks.h"
#include "ProfilerBridge.h"
#include "CaptureTiming.h"
#include "Protocol.h"
#include "WinSupport.h"
#include <wrl/client.h>
#include <algorithm>
#include <atomic>
#include <array>
#include <cstring>
#include <memory>
#include <unordered_map>
#include <condition_variable>
#include <map>
#include <mutex>
#include <thread>
#include <intrin.h>

extern "C" void ManagedEnterStub();
extern "C" void ManagedLeaveStub();
extern "C" void ManagedTailcallStub();
extern "C" void ManagedEnter2Stub();
extern "C" void ManagedLeave2Stub();
extern "C" void ManagedTailcall2Stub();
extern "C" uint32_t ManagedXStateMask = 0;
constexpr uint32_t DefaultXStateBytes = 512;
extern "C" uint32_t ManagedXStateBytes = DefaultXStateBytes;

namespace Detourist
{
using Microsoft::WRL::ComPtr;
constexpr uint32_t MaxManagedDepth = 4096;
constexpr size_t MaxQueuedModules = 4096;
constexpr size_t MaxInstrumentedMethods = 131072;
constexpr size_t RejitBatchSize = 1024;
constexpr size_t ClrEnumBatchSize = 128;
constexpr ULONG MaxArrayRank = 32;
constexpr size_t ArgumentRangeBufferCount = 128;
constexpr size_t GuidStringCapacity = 40;
constexpr int CpuidFeatureLeaf = 1;
constexpr int CpuidXSaveLeaf = 0xD;
constexpr int CpuidXSaveBit = 1 << 26;
constexpr int CpuidOsXSaveBit = 1 << 27;
constexpr uint32_t XStateVectorMask = 0xE7;
constexpr uint32_t MinXSaveBytes = 576;
constexpr uint32_t MaxXSaveBytes = 3072;
constexpr uint32_t FirstDynamicXStateComponent = 2;
constexpr uint32_t MaxXStateComponent = 8;
std::atomic<uint32_t> ProfilerObjects = 0;
class Profiler;
void WINAPI AttachedManagedCall(ManagedMethod* method, const ManagedArgument* arguments, ManagedCallPhase phase);
std::atomic<Profiler*> LegacyProfiler = nullptr;
SRWLOCK RuntimeProfilersLock = SRWLOCK_INIT;
Profiler* RuntimeProfilers = nullptr;

bool SafeRead(void* destination, const void* source, size_t bytes)
{
    __try
    {
        if (bytes) memcpy(destination, source, bytes);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

struct ManagedFrame
{
    ManagedCallState state;
    ManagedMethod* method = nullptr;
    uint32_t constructed = 0;
    uint32_t bufferLimit = 0;
    uint32_t outputMask = 0;
    uint32_t pendingMoveMask = 0;
    std::array<uint64_t, MaximumArguments> outputValues{};
};

struct ManagedThread;
SRWLOCK ManagedThreadsLock = SRWLOCK_INIT;
ManagedThread* ManagedThreads = nullptr;

struct ManagedThread
{
    static constexpr uint32_t BlockFrames = 64;
    std::vector<std::unique_ptr<ManagedFrame[]>> blocks;
    std::vector<std::byte> payload;
    std::vector<std::pair<void*, FunctionID>> unwinds;
    uint32_t depth = 0;
    uint32_t overflow = 0;
    ManagedThread* next = nullptr;

    ManagedThread()
    {
        AcquireSRWLockExclusive(&ManagedThreadsLock);
        next = ManagedThreads;
        ManagedThreads = this;
        ReleaseSRWLockExclusive(&ManagedThreadsLock);
    }
    ~ManagedThread()
    {
        AcquireSRWLockExclusive(&ManagedThreadsLock);
        auto link = &ManagedThreads;
        while (*link && *link != this) link = &(*link)->next;
        if (*link) *link = next;
        ReleaseSRWLockExclusive(&ManagedThreadsLock);
    }

    ManagedFrame& At(uint32_t index) { return blocks[index / BlockFrames][index % BlockFrames]; }
    uint32_t FindDepth(ManagedMethod* method)
    {
        auto index = depth;
        while (index && At(index - 1).method != method) --index;
        return index;
    }
    ManagedFrame* Push(ManagedMethod* method)
    {
        if (overflow || depth >= MaxManagedDepth) { ++overflow; return nullptr; }
        auto block = depth / BlockFrames;
        if (block == blocks.size()) blocks.push_back(std::make_unique<ManagedFrame[]>(BlockFrames));
        auto& frame = At(depth++);
        frame.method = method;
        frame.constructed = 0;
        frame.outputMask = frame.pendingMoveMask = 0;
        return &frame;
    }
};
thread_local ManagedThread ManagedFrames;
thread_local bool AttachedSnapshotActive = false;

BOOL WINAPI GuardAttachedSnapshot(BOOL enter)
{
    if (enter && AttachedSnapshotActive) return FALSE;
    AttachedSnapshotActive = enter != FALSE;
    return TRUE;
}

class CallbackScope
{
public:
    // Native error preservation belongs to profiler bookkeeping, including nested observer callbacks.
    explicit CallbackScope(const ProfilerBridge& bridge) : bridge_(bridge), previous_(bridge.guard(TRUE)),
        error_(GetLastError()), observation_(bridge.captureClock(), Clock()) {}
    ~CallbackScope() { observation_.Reset(); SetLastError(error_); bridge_.guard(previous_); }
    bool Reentered() const { return previous_ != FALSE; }
private:
    const ProfilerBridge& bridge_;
    BOOL previous_;
    DWORD error_;
    CaptureObservation observation_;
};

class Profiler final : public ProfilerCallbacks
{
public:
    Profiler() { ++ProfilerObjects; }
    ~Profiler()
    {
        ForgetNativeCode();
        AcquireSRWLockExclusive(&RuntimeProfilersLock);
        auto link = &RuntimeProfilers;
        while (*link && *link != this) link = &(*link)->nextRuntime;
        if (*link) *link = nextRuntime;
        ReleaseSRWLockExclusive(&RuntimeProfilersLock);
        auto previous = this;
        LegacyProfiler.compare_exchange_strong(previous, nullptr);
        --ProfilerObjects;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** result) override
    {
        if (!result) return E_POINTER;
        *result = nullptr;
        if (iid != IID_IUnknown && iid != __uuidof(ICorProfilerCallback) &&
            iid != __uuidof(ICorProfilerCallback2) && iid != __uuidof(ICorProfilerCallback3) &&
            iid != __uuidof(ICorProfilerCallback4)) return E_NOINTERFACE;
        *result = static_cast<ICorProfilerCallback4*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        auto remaining = --references_;
        if (!remaining) delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE Initialize(IUnknown* information) override;
    HRESULT STDMETHODCALLTYPE InitializeForAttach(IUnknown* information, void*, UINT) override
    {
        return InitializeRuntime(information, true);
    }
    HRESULT STDMETHODCALLTYPE Shutdown() override
    {
        active_ = false;
        ForgetNativeCode();
        rejitWorker_.request_stop();
        queuedModulesChanged_.notify_all();
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ProfilerAttachComplete() override;
    HRESULT STDMETHODCALLTYPE ModuleLoadFinished(ModuleID module, HRESULT result) override;
    HRESULT STDMETHODCALLTYPE AssemblyLoadFinished(AssemblyID assembly, HRESULT result) override
    {
        if (FAILED(result)) return S_OK;
        CallbackScope scope(bridge_);
        try
        {
            ModuleID manifest = 0;
            if (SUCCEEDED(information_->GetAssemblyInfo(assembly, 0, nullptr, nullptr, nullptr, &manifest)))
                classes_.ObserveModule(information_.Get(), manifest);
        }
        catch (...) { Failure(); }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ModuleUnloadFinished(ModuleID module, HRESULT) override
    {
        CallbackScope scope(bridge_);
        {
            std::lock_guard lock(nativeCodeLock_);
            for (auto item = nativeCode_.begin(); item != nativeCode_.end();)
            {
                if (item->second.module != module) { ++item; continue; }
                for (const auto& code : item->second.ranges)
                    bridge_.nativeCode(code.startAddress, code.size, FALSE);
                item = nativeCode_.erase(item);
            }
        }
        classes_.ForgetModule(module);
        std::lock_guard lock(instrumentationLock_);
        auto first = instrumentation_.lower_bound({module, 0});
        auto last = instrumentation_.upper_bound({module, UINT32_MAX});
        instrumentation_.erase(first, last);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE JITCompilationStarted(FunctionID function, BOOL) override;
    HRESULT STDMETHODCALLTYPE JITCompilationFinished(FunctionID function, HRESULT result, BOOL) override
    {
        if (FAILED(result) || !active_) return S_OK;
        CallbackScope scope(bridge_);
        try { ObserveNativeCode(function); }
        catch (...) { Failure(); }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetReJITParameters(ModuleID module, mdMethodDef method,
        ICorProfilerFunctionControl* control) override
    {
        CallbackScope scope(bridge_);
        auto result = Instrument(module, method, control);
        if (FAILED(result)) Failure();
        return result;
    }
    HRESULT STDMETHODCALLTYPE ReJITCompilationFinished(FunctionID function, ReJITID, HRESULT result, BOOL) override;
    HRESULT STDMETHODCALLTYPE ReJITError(ModuleID, mdMethodDef, FunctionID, HRESULT result) override
    {
        if (result != CORPROF_E_DATAINCOMPLETE && result != CORPROF_E_FUNCTION_NOT_IL) Failure();
        return S_OK;
    }
    Profiler* nextRuntime = nullptr;
    bool IsCurrentThreadManaged()
    {
        ThreadID thread = 0;
        return active_ && SUCCEEDED(information_->GetCurrentThreadID(&thread)) && thread;
    }
    HRESULT STDMETHODCALLTYPE JITInlining(FunctionID, FunctionID, BOOL* inlineMethod) override
    {
        if (inlineMethod) *inlineMethod = FALSE;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchStarted(FunctionID, BOOL* useImage) override
    {
        if (useImage) *useImage = FALSE;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE FunctionUnloadStarted(FunctionID function) override
    {
        CallbackScope scope(bridge_);
        ForgetNativeCode(function);
        AcquireSRWLockExclusive(&methodsLock_);
        methods_.erase(function);
        ReleaseSRWLockExclusive(&methodsLock_);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ClassLoadFinished(ClassID type, HRESULT result) override
    {
        CallbackScope scope(bridge_);
        try { if (SUCCEEDED(result)) classes_.Observe(information_.Get(), type); }
        catch (...) { Failure(); }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ClassUnloadStarted(ClassID type) override
    {
        CallbackScope scope(bridge_);
        classes_.Forget(type);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionEnter(FunctionID function) override
    {
        CallbackScope scope(bridge_);
        try { ManagedFrames.unwinds.emplace_back(this, function); }
        catch (...) { bridge_.status(static_cast<uint32_t>(ManagedState::Failed)); }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionLeave() override;
    HRESULT STDMETHODCALLTYPE GarbageCollectionStarted(int count, BOOL collected[], COR_PRF_GC_REASON) override;
    HRESULT STDMETHODCALLTYPE GarbageCollectionFinished() override;
    HRESULT STDMETHODCALLTYPE MovedReferences(ULONG count, ObjectID before[], ObjectID after[], ULONG bytes[]) override
    {
        return RelocateReferences(count, before, after, bytes);
    }
    HRESULT STDMETHODCALLTYPE SurvivingReferences(ULONG count, ObjectID starts[], ULONG bytes[]) override
    {
        return RelocateReferences(count, starts, starts, bytes);
    }
    HRESULT STDMETHODCALLTYPE MovedReferences2(ULONG count, ObjectID before[], ObjectID after[],
        SIZE_T bytes[]) override
    {
        return RelocateReferences(count, before, after, bytes);
    }
    HRESULT STDMETHODCALLTYPE SurvivingReferences2(ULONG count, ObjectID starts[], SIZE_T bytes[]) override
    {
        return RelocateReferences(count, starts, starts, bytes);
    }
    static UINT_PTR STDMETHODCALLTYPE Map(FunctionID function, void* context, BOOL* hook);
    static UINT_PTR STDMETHODCALLTYPE LegacyMap(FunctionID function, BOOL* hook)
    {
        auto self = LegacyProfiler.load();
        if (self) return Map(function, self, hook);
        *hook = FALSE;
        return 0;
    }
    void Enter(ManagedMethod* method, COR_PRF_ELT_INFO information,
        COR_PRF_FUNCTION_ARGUMENT_INFO* legacyArguments = nullptr);
    void Leave(ManagedMethod* method, COR_PRF_ELT_INFO information, uint32_t flags,
        COR_PRF_FUNCTION_ARGUMENT_RANGE* legacyResult = nullptr);
    void EndTop(uint32_t flags, uint64_t result = 0);
    void Failure() { incomplete_ = true; bridge_.status(static_cast<uint32_t>(ManagedState::Failed)); }
    void CaptureAttached(ManagedMethod* method, const ManagedArgument* arguments, ManagedCallPhase phase);
    void FailedLeave(ManagedMethod* method)
    {
        CallbackScope scope(bridge_);
        bridge_.status(static_cast<uint32_t>(ManagedState::Failed));
        ManagedFrames.payload.clear();
        auto index = ManagedFrames.FindDepth(method);
        if (index) while (ManagedFrames.depth >= index) EndTop(Failed | Unwound);
    }

private:
    HRESULT InitializeRuntime(IUnknown* information, bool attached);
    HRESULT Instrument(ModuleID module, mdMethodDef token, ICorProfilerFunctionControl* control,
        FunctionID function = 0);
    void RequestModuleRejit(ModuleID module);
    void ObserveNativeCode(FunctionID function, ReJITID version = 0);
    void ForgetNativeCode(FunctionID function = 0);
    template<class Visitor> void VisitOutputFrames(Visitor visitor);
    template<class Size> HRESULT RelocateReferences(ULONG count, ObjectID before[], ObjectID after[], Size bytes[]);
    void Snapshot(uint32_t parameter, ValueKind kind, const void* address, uint64_t bytes, uint32_t limit);
    void ArraySnapshot(uint32_t parameter, const void* address, uint64_t bytes, uint32_t stride, uint32_t limit);
    void Unavailable(uint32_t parameter, uint64_t bytes);
    void ObjectSnapshot(uint32_t parameter, const ManagedType& type, uint64_t value, uint32_t limit);
    std::atomic<ULONG> references_ = 1;
    std::atomic<bool> active_ = false;
    ComPtr<ICorProfilerInfo2> information_;
    ComPtr<ICorProfilerInfo3> modernInformation_;
    ComPtr<ICorProfilerInfo4> rejitInformation_;
    bool attached_ = false;
    std::atomic<bool> incomplete_ = false;
    ProfilerBridge bridge_{};
    struct NativeCode
    {
        ModuleID module;
        std::vector<COR_PRF_CODE_INFO> ranges;
    };
    std::mutex nativeCodeLock_;
    std::map<FunctionID, NativeCode> nativeCode_;
    ULONG stringLengthOffset_ = 0;
    ULONG stringDataOffset_ = 0;
    SRWLOCK methodsLock_ = SRWLOCK_INIT;
    std::unordered_map<FunctionID, ManagedMethod*> methods_;
    std::vector<std::unique_ptr<ManagedMethod>> definitions_;
    ManagedClasses classes_;
    struct Instrumentation
    {
        ManagedMethod* method = nullptr;
        std::vector<BYTE> body;
        bool applied = false;
    };
    std::mutex instrumentationLock_, queuedModulesLock_;
    std::map<std::pair<ModuleID, mdMethodDef>, Instrumentation> instrumentation_;
    std::vector<ModuleID> queuedModules_;
    std::condition_variable_any queuedModulesChanged_;
    std::jthread rejitWorker_;
};

HRESULT Profiler::Initialize(IUnknown* information)
{
    return InitializeRuntime(information, false);
}

HRESULT Profiler::InitializeRuntime(IUnknown* information, bool attached)
{
    auto agent = GetModuleHandleW(L"DetouristAgent.dll");
    auto getBridge = agent ? reinterpret_cast<GetProfilerBridge>(GetProcAddress(agent,
        "DetouristGetProfilerBridge")) : nullptr;
    if (!getBridge || !getBridge(ProfilerBridgeVersion, &bridge_)) return E_FAIL;
    CallbackScope scope(bridge_);
    auto result = information->QueryInterface(__uuidof(ICorProfilerInfo2),
        reinterpret_cast<void**>(information_.GetAddressOf()));
    if (FAILED(result)) { bridge_.status(static_cast<uint32_t>(ManagedState::Failed)); return result; }
    information_.As(&modernInformation_);
    attached_ = attached;
    result = information_.As(&rejitInformation_);
    if (attached_ && FAILED(result))
    {
        bridge_.status(static_cast<uint32_t>(ManagedState::Failed));
        return result;
    }

    // Select the state components used by managed vector intrinsics without allocating an AMX tile buffer.
    int registers[4]{};
    __cpuid(registers, CpuidFeatureLeaf);
    if ((registers[2] & CpuidXSaveBit) && (registers[2] & CpuidOsXSaveBit))
    {
        auto mask = static_cast<uint32_t>(_xgetbv(0)) & XStateVectorMask;
        uint32_t size = MinXSaveBytes;
        for (uint32_t component = FirstDynamicXStateComponent; component < MaxXStateComponent; ++component)
        {
            if (!(mask & (uint32_t{1} << component))) continue;
            __cpuidex(registers, CpuidXSaveLeaf, static_cast<int>(component));
            size = std::max(size, static_cast<uint32_t>(registers[0] + registers[1]));
        }
        if (size <= MaxXSaveBytes) { ManagedXStateBytes = size; ManagedXStateMask = mask; }
    }
    ULONG bufferLengthOffset = 0;
    if (modernInformation_) modernInformation_->GetStringLayout2(&stringLengthOffset_, &stringDataOffset_);
    else information_->GetStringLayout(&bufferLengthOffset, &stringLengthOffset_, &stringDataOffset_);
    auto mask = static_cast<DWORD>(COR_PRF_MONITOR_ENTERLEAVE |
        COR_PRF_ENABLE_FUNCTION_ARGS | COR_PRF_ENABLE_FUNCTION_RETVAL | COR_PRF_MONITOR_EXCEPTIONS |
        COR_PRF_MONITOR_FUNCTION_UNLOADS | COR_PRF_MONITOR_GC | COR_PRF_DISABLE_INLINING);
    if constexpr (sizeof(void*) == 4) mask |= COR_PRF_MONITOR_JIT_COMPILATION;
    mask |= modernInformation_ ? COR_PRF_DISABLE_ALL_NGEN_IMAGES : COR_PRF_MONITOR_CACHE_SEARCHES;
    if (attached_)
        mask = COR_PRF_MONITOR_MODULE_LOADS | COR_PRF_MONITOR_JIT_COMPILATION |
            COR_PRF_MONITOR_EXCEPTIONS | COR_PRF_ENABLE_REJIT;
    result = information_->SetEventMask(mask | COR_PRF_MONITOR_CLASS_LOADS | COR_PRF_MONITOR_MODULE_LOADS |
        COR_PRF_MONITOR_ASSEMBLY_LOADS);

    // Use the callback ABI and string layout supplied by the loaded runtime.
    if (!attached_ && modernInformation_)
    {
        if (SUCCEEDED(result)) result = modernInformation_->SetFunctionIDMapper2(&Map, this);
        if (SUCCEEDED(result)) result = modernInformation_->SetEnterLeaveFunctionHooks3WithInfo(
            reinterpret_cast<FunctionEnter3WithInfo*>(&ManagedEnterStub),
            reinterpret_cast<FunctionLeave3WithInfo*>(&ManagedLeaveStub),
            reinterpret_cast<FunctionTailcall3WithInfo*>(&ManagedTailcallStub));
    }
    else if (!attached_)
    {
        LegacyProfiler = this;
        if (SUCCEEDED(result)) result = information_->SetFunctionIDMapper(&LegacyMap);
        if (SUCCEEDED(result)) result = information_->SetEnterLeaveFunctionHooks2(
            reinterpret_cast<FunctionEnter2*>(&ManagedEnter2Stub),
            reinterpret_cast<FunctionLeave2*>(&ManagedLeave2Stub),
            reinterpret_cast<FunctionTailcall2*>(&ManagedTailcall2Stub));
    }
    if (FAILED(result)) { bridge_.status(static_cast<uint32_t>(ManagedState::Failed)); return result; }
    active_ = true;
    AcquireSRWLockExclusive(&RuntimeProfilersLock);
    nextRuntime = RuntimeProfilers;
    RuntimeProfilers = this;
    ReleaseSRWLockExclusive(&RuntimeProfilersLock);
    bridge_.status(static_cast<uint32_t>(attached_ ? ManagedState::Attaching : ManagedState::Active));
    return S_OK;
}

HRESULT Profiler::ProfilerAttachComplete()
{
    CallbackScope scope(bridge_);
    try
    {
        if constexpr (sizeof(void*) == 4)
        {
            // Existing JIT frames must keep their CLR addresses when instruction capture joins the process.
            ComPtr<ICorProfilerFunctionEnum> functions;
            auto result = rejitInformation_->EnumJITedFunctions2(&functions);
            if (FAILED(result)) result = modernInformation_->EnumJITedFunctions(&functions);
            if (SUCCEEDED(result))
            {
                COR_PRF_FUNCTION batch[ClrEnumBatchSize];
                ULONG count = 0;
                while (SUCCEEDED(functions->Next(_countof(batch), batch, &count)) && count)
                    for (ULONG index = 0; index < count; ++index)
                        ObserveNativeCode(batch[index].functionId, batch[index].reJitId);
            }
        }

        // Request replacements from a native worker because ReJIT can suspend managed threads.
        rejitWorker_ = std::jthread([this](std::stop_token stop)
        {
            CallbackScope scope(bridge_);
            try
            {
                rejitInformation_->InitializeCurrentThread();
                ComPtr<ICorProfilerModuleEnum> modules;
                if (FAILED(modernInformation_->EnumModules(&modules))) { Failure(); return; }
                ModuleID batch[ClrEnumBatchSize];
                ULONG count = 0;
                std::vector<ModuleID> loaded;
                while (!stop.stop_requested() && SUCCEEDED(modules->Next(_countof(batch), batch, &count)) && count)
                    for (ULONG index = 0; index < count && !stop.stop_requested(); ++index)
                    {
                        classes_.ObserveModule(information_.Get(), batch[index]);
                        loaded.push_back(batch[index]);
                    }
                for (auto module : loaded)
                    if (!stop.stop_requested()) RequestModuleRejit(module);
                if (!stop.stop_requested())
                    bridge_.status(static_cast<uint32_t>(incomplete_ ? ManagedState::Failed : ManagedState::Active));
                while (!stop.stop_requested())
                {
                    std::vector<ModuleID> queued;
                    {
                        std::unique_lock lock(queuedModulesLock_);
                        queuedModulesChanged_.wait(lock, stop, [this]() { return !queuedModules_.empty(); });
                        queued.swap(queuedModules_);
                    }
                    for (auto module : queued)
                        if (!stop.stop_requested()) RequestModuleRejit(module);
                }
            }
            catch (...) { Failure(); }
        });
        return S_OK;
    }
    catch (...) { Failure(); return E_OUTOFMEMORY; }
}

HRESULT Profiler::ModuleLoadFinished(ModuleID module, HRESULT result)
{
    if (FAILED(result)) return S_OK;
    CallbackScope scope(bridge_);
    try
    {
        classes_.ObserveModule(information_.Get(), module);
        if (!attached_) return S_OK;
        std::lock_guard lock(queuedModulesLock_);
        if (queuedModules_.size() < MaxQueuedModules) queuedModules_.push_back(module);
        else Failure();
        queuedModulesChanged_.notify_one();
    }
    catch (...) { Failure(); }
    return S_OK;
}

void Profiler::RequestModuleRejit(ModuleID module)
{
    classes_.ObserveModule(information_.Get(), module);
    ComPtr<IMetaDataImport> metadata;
    if (FAILED(information_->GetModuleMetaData(module, ofRead, IID_IMetaDataImport,
        reinterpret_cast<IUnknown**>(metadata.GetAddressOf())))) return;
    auto close = [&](void* enumeration) { if (enumeration) metadata->CloseEnum(enumeration); };
    std::vector<mdMethodDef> methods;
    std::vector<ModuleID> owners;
    methods.reserve(RejitBatchSize);
    owners.reserve(RejitBatchSize);
    auto request = [&]()
    {
        if (!methods.empty() && active_ && FAILED(rejitInformation_->RequestReJIT(
            static_cast<ULONG>(methods.size()), owners.data(), methods.data()))) Failure();
        methods.clear();
        owners.clear();
    };
    auto appendType = [&](mdTypeDef type)
    {
        HCORENUM methodEnumeration = nullptr;
        mdMethodDef batch[ClrEnumBatchSize];
        ULONG count = 0;
        auto result = metadata->EnumMethods(&methodEnumeration, type, batch, _countof(batch), &count);
        std::unique_ptr<void, decltype(close)> owner(methodEnumeration, close);
        while (active_ && SUCCEEDED(result) && count)
        {
            for (ULONG index = 0; index < count; ++index)
            {
                ULONG rva = 0;
                DWORD attributes = 0, implementation = 0;
                if (FAILED(metadata->GetMethodProps(batch[index], nullptr, nullptr, 0, nullptr, &attributes,
                    nullptr, nullptr, &rva, &implementation)) || !rva ||
                    (attributes & (mdAbstract | mdPinvokeImpl)) ||
                    (implementation & miCodeTypeMask) != miIL || (implementation & miInternalCall)) continue;
                methods.push_back(batch[index]);
                owners.push_back(module);
                if (methods.size() == RejitBatchSize) request();
            }
            result = metadata->EnumMethods(&methodEnumeration, type, batch, _countof(batch), &count);
        }
    };

    // Recompile application callers too, so their existing framework inlines become observable calls.
    appendType(mdTypeDefNil);
    HCORENUM typeEnumeration = nullptr;
    mdTypeDef types[ClrEnumBatchSize];
    ULONG count = 0;
    auto result = metadata->EnumTypeDefs(&typeEnumeration, types, _countof(types), &count);
    std::unique_ptr<void, decltype(close)> owner(typeEnumeration, close);
    while (active_ && SUCCEEDED(result) && count)
    {
        for (ULONG index = 0; index < count; ++index) appendType(types[index]);
        result = metadata->EnumTypeDefs(&typeEnumeration, types, _countof(types), &count);
    }
    request();
}

HRESULT Profiler::Instrument(ModuleID module, mdMethodDef token, ICorProfilerFunctionControl* control,
    FunctionID function)
{
    if (!attached_ || !active_) return S_OK;
    try
    {
        if (control)
        {
            auto result = control->SetCodegenFlags(COR_PRF_DISABLE_INLINING);
            if (FAILED(result)) return result;
        }
        std::lock_guard lock(instrumentationLock_);
        auto [position, inserted] = instrumentation_.try_emplace({module, token});
        auto& instrumentation = position->second;
        if (inserted)
        {
            if (instrumentation_.size() > MaxInstrumentedMethods) return E_OUTOFMEMORY;
            auto method = std::make_unique<ManagedMethod>();
            if (!(function && ReadManagedMethod(information_.Get(), function, *method, classes_, false)) &&
                !ReadManagedMethod(information_.Get(), module, token, *method)) return S_OK;
            LPCBYTE original = nullptr;
            ULONG originalBytes = 0;
            auto result = information_->GetILFunctionBody(module, token, &original, &originalBytes);
            if (FAILED(result)) return result == CORPROF_E_FUNCTION_NOT_IL ? S_OK : result;
            method->owner = this;
            if (FAILED(result = InstrumentManagedMethod(information_.Get(), classes_.CoreLibrary(), method.get(),
                {original, originalBytes}, stringLengthOffset_, stringDataOffset_, &AttachedManagedCall,
                &GuardAttachedSnapshot, instrumentation.body))) return result;
            DynamicApiMetadata metadata{};
            metadata.argumentCount = method->instrumentedArguments;
            auto moduleName = Utf8(method->moduleName), name = Utf8(method->name);
            strncpy_s(metadata.module, moduleName.c_str(), _TRUNCATE);
            strncpy_s(metadata.name, name.c_str(), _TRUNCATE);
            auto parameters = method->decodedArguments ? method->parameters :
                L"Raw CLR argument regions; " + method->parameters;
            wcsncpy_s(metadata.parameters, parameters.c_str(), _TRUNCATE);
            method->api = bridge_.registerApi(&metadata, method->layout.data(),
                static_cast<uint32_t>(method->layout.size()));
            if (!method->api) return E_OUTOFMEMORY;
            instrumentation.method = method.get();
            definitions_.push_back(std::move(method));
        }
        if (!instrumentation.method) return S_OK;
        if (control) return control->SetILFunctionBody(static_cast<ULONG>(instrumentation.body.size()),
            instrumentation.body.data());
        if (instrumentation.applied) return S_OK;
        ComPtr<IMethodMalloc> allocator;
        auto result = information_->GetILFunctionBodyAllocator(module, &allocator);
        if (FAILED(result)) return result;
        auto memory = static_cast<BYTE*>(allocator->Alloc(static_cast<ULONG>(instrumentation.body.size())));
        if (!memory) return E_OUTOFMEMORY;
        memcpy(memory, instrumentation.body.data(), instrumentation.body.size());
        result = information_->SetILFunctionBody(module, token, memory);
        if (SUCCEEDED(result)) instrumentation.applied = true;
        return result;
    }
    catch (...) { return E_OUTOFMEMORY; }
}

HRESULT Profiler::JITCompilationStarted(FunctionID function, BOOL)
{
    if (!attached_ || !active_) return S_OK;
    CallbackScope scope(bridge_);
    ClassID type = 0;
    ModuleID module = 0;
    mdToken token = 0;
    if (SUCCEEDED(information_->GetFunctionInfo(function, &type, &module, &token)))
        if (FAILED(Instrument(module, token, nullptr, function))) Failure();
    return S_OK;
}

void Profiler::ObserveNativeCode(FunctionID function, ReJITID version)
{
    if (sizeof(void*) != 4) return;
    ULONG32 count = 0;
    auto read = [&](ULONG32 capacity, COR_PRF_CODE_INFO* code)
    {
        return version && rejitInformation_ ?
            rejitInformation_->GetCodeInfo3(function, version, capacity, &count, code) :
            information_->GetCodeInfo2(function, capacity, &count, code);
    };
    if (FAILED(read(0, nullptr)) || !count) return;
    std::vector<COR_PRF_CODE_INFO> code(count);
    if (FAILED(read(static_cast<ULONG32>(code.size()), code.data())) || count > code.size()) return;
    code.resize(count);
    ClassID type = 0;
    ModuleID module = 0;
    mdToken token = 0;
    if (FAILED(information_->GetFunctionInfo(function, &type, &module, &token))) return;
    std::lock_guard lock(nativeCodeLock_);
    if (!active_) return;
    auto& entry = nativeCode_[function];
    entry.module = module;
    auto& known = entry.ranges;
    for (const auto& range : code)
    {
        if (!range.size || std::any_of(known.begin(), known.end(), [&](const auto& item)
            { return item.startAddress == range.startAddress && item.size == range.size; })) continue;
        known.push_back(range);
        bridge_.nativeCode(range.startAddress, range.size, TRUE);
    }
}

void Profiler::ForgetNativeCode(FunctionID function)
{
    std::lock_guard lock(nativeCodeLock_);
    auto first = function ? nativeCode_.find(function) : nativeCode_.begin();
    auto last = function && first != nativeCode_.end() ? std::next(first) : nativeCode_.end();
    for (auto item = first; item != last; ++item)
        for (const auto& code : item->second.ranges) bridge_.nativeCode(code.startAddress, code.size, FALSE);
    nativeCode_.erase(first, last);
}

HRESULT Profiler::ReJITCompilationFinished(FunctionID function, ReJITID version, HRESULT result, BOOL)
{
    if (FAILED(result)) { Failure(); return S_OK; }
    if (!attached_ || !active_) return S_OK;
    CallbackScope scope(bridge_);
    try
    {
        ObserveNativeCode(function, version);
        ClassID type = 0;
        ModuleID module = 0;
        mdToken token = 0;
        if (FAILED(information_->GetFunctionInfo(function, &type, &module, &token))) return S_OK;
        std::lock_guard lock(instrumentationLock_);
        auto found = instrumentation_.find({module, token});
        auto method = found == instrumentation_.end() ? nullptr : found->second.method;
        if (!method || !method->layout.empty()) return S_OK;

        // The completed function supplies loaded layouts for receivers, parameters and returns.
        ManagedMethod loaded;
        if (ReadManagedMethod(information_.Get(), function, loaded, classes_, false) && !loaded.layout.empty() &&
            bridge_.updateLayout(method->api, loaded.layout.data(), static_cast<uint32_t>(loaded.layout.size())))
            method->layout = std::move(loaded.layout);
    }
    catch (...) { Failure(); }
    return S_OK;
}

UINT_PTR STDMETHODCALLTYPE Profiler::Map(FunctionID function, void* context, BOOL* hook)
{
    auto self = static_cast<Profiler*>(context);
    *hook = FALSE;
    CallbackScope scope(self->bridge_);
    if (!self->active_) return 0;
    AcquireSRWLockExclusive(&self->methodsLock_);
    ManagedMethod* mapped = nullptr;
    try
    {
        if (auto found = self->methods_.find(function); found != self->methods_.end()) mapped = found->second;
        else if (self->methods_.size() >= MaxInstrumentedMethods)
        {
            self->bridge_.status(static_cast<uint32_t>(ManagedState::Failed));
        }
        else
        {
            auto method = std::make_unique<ManagedMethod>();
            if (ReadManagedMethod(self->information_.Get(), function, *method, self->classes_))
            {
                DynamicApiMetadata metadata{};
                metadata.argumentCount = method->decodedArguments ?
                    static_cast<uint32_t>(std::min<size_t>(method->arguments.size(), MaximumArguments)) :
                    RawArgumentCount;
                auto module = Utf8(method->moduleName), name = Utf8(method->name);
                method->nativeDelegate = method->name.starts_with(
                    L"System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer(");
                strncpy_s(metadata.module, module.c_str(), _TRUNCATE);
                strncpy_s(metadata.name, name.c_str(), _TRUNCATE);
                auto parameters = method->decodedArguments ? method->parameters :
                    L"Raw CLR argument regions; " + method->parameters;
                wcsncpy_s(metadata.parameters, parameters.c_str(), _TRUNCATE);
                method->api = self->bridge_.registerApi(&metadata, method->layout.data(),
                    static_cast<uint32_t>(method->layout.size()));
                method->owner = self;
                if (method->api)
                {
                    mapped = method.get();
                    self->definitions_.push_back(std::move(method));
                }
            }
            self->methods_[function] = mapped;
        }
    }
    catch (...)
    {
        self->bridge_.status(static_cast<uint32_t>(ManagedState::Failed));
    }
    ReleaseSRWLockExclusive(&self->methodsLock_);
    *hook = mapped != nullptr;
    return reinterpret_cast<UINT_PTR>(mapped);
}

void Profiler::Snapshot(uint32_t parameter, ValueKind kind, const void* address, uint64_t bytes, uint32_t limit)
{
    auto count = static_cast<uint32_t>(std::min<uint64_t>(bytes, limit));
    auto position = ManagedFrames.payload.size();
    ManagedFrames.payload.resize(position + sizeof(Value) + count);
    Value value{parameter, kind, count < bytes ? Truncated : 0u, count, bytes};
    if (!SafeRead(ManagedFrames.payload.data() + position + sizeof(Value), address, count))
    {
        value.flags |= Unreadable;
        value.capturedBytes = 0;
        ManagedFrames.payload.resize(position + sizeof(Value));
    }
    memcpy(ManagedFrames.payload.data() + position, &value, sizeof(value));
}

void Profiler::Unavailable(uint32_t parameter, uint64_t bytes)
{
    auto position = ManagedFrames.payload.size();
    ManagedFrames.payload.resize(position + sizeof(Value));
    Value value{parameter, ValueKind::Bytes, Unreadable, 0, bytes};
    memcpy(ManagedFrames.payload.data() + position, &value, sizeof(value));
}

void Profiler::ArraySnapshot(uint32_t parameter, const void* address, uint64_t bytes, uint32_t stride, uint32_t limit)
{
    // Keep array shape independent of the value-byte cap, including a partially captured final element.
    if (bytes && (!stride || bytes % stride || bytes / stride > UINT32_MAX))
    {
        Unavailable(parameter, bytes);
        return;
    }
    auto position = ManagedFrames.payload.size();
    Snapshot(parameter, ValueKind::ManagedArray, address, bytes, limit);
    uint64_t shape = (uint64_t{stride} << 32) | (stride ? bytes / stride : 0);
    memcpy(ManagedFrames.payload.data() + position + offsetof(Value, originalBytes), &shape, sizeof(shape));
}

void Profiler::ObjectSnapshot(uint32_t parameter, const ManagedType& type, uint64_t value, uint32_t limit)
{
    if (!value) return;
    if (type.byReference)
    {
        if (type.referencedBytes)
            Snapshot(parameter, ValueKind::Bytes, reinterpret_cast<const void*>(value), type.referencedBytes, limit);
        if (type.element != ELEMENT_TYPE_STRING && !type.arrayRank) return;
        uintptr_t reference = 0;
        if (!SafeRead(&reference, reinterpret_cast<const void*>(value), sizeof(reference))) return;
        value = reference;
    }
    if (!value) return;
    if (type.element == ELEMENT_TYPE_STRING && stringDataOffset_)
    {
        uint32_t length = 0;
        if (SafeRead(&length, reinterpret_cast<const void*>(value + stringLengthOffset_), sizeof(length)))
            Snapshot(parameter, ValueKind::Utf16, reinterpret_cast<const void*>(value + stringDataOffset_),
                uint64_t{length} * sizeof(wchar_t), limit);
    }
    else if (type.arrayRank)
    {
        ULONG rank = type.arrayRank;
        if (rank == UINT32_MAX)
        {
            ClassID identity = 0, element = 0;
            CorElementType category;
            if (FAILED(information_->GetClassFromObject(static_cast<ObjectID>(value), &identity)) ||
                information_->IsArrayClass(identity, &category, &element, &rank) != S_OK) return;
        }
        if (!rank || rank > MaxArrayRank) return;
        ULONG32 lengths[MaxArrayRank]{};
        int lower[MaxArrayRank]{};
        BYTE* data = nullptr;
        if (FAILED(information_->GetArrayObjectInfo(static_cast<ObjectID>(value), rank,
            lengths, lower, &data))) return;
        uint64_t length = std::find(lengths, lengths + rank, 0u) == lengths + rank ? 1 : 0;
        for (uint32_t dimension = 0; dimension < rank; ++dimension)
        {
            length *= lengths[dimension];
            if (length > UINT32_MAX) return;
        }
        if (type.elementBytes)
        {
            Snapshot(parameter, ValueKind::Bytes, data, length * type.elementBytes, limit);
            return;
        }

        // CLR object sizes include the pointer-sized header before ObjectID, but exclude heap alignment padding.
        SIZE_T objectBytes = 0;
        HRESULT result;
        if (rejitInformation_) result = rejitInformation_->GetObjectSize2(static_cast<ObjectID>(value), &objectBytes);
        else
        {
            ULONG legacyBytes = 0;
            result = information_->GetObjectSize(static_cast<ObjectID>(value), &legacyBytes);
            objectBytes = legacyBytes;
        }
        auto start = reinterpret_cast<uintptr_t>(data);
        if (FAILED(result) || start < value || start - value > objectBytes ||
            objectBytes - (start - value) < sizeof(uintptr_t)) return;
        auto bytes = objectBytes - (start - value) - sizeof(uintptr_t);
        if (length ? !bytes || bytes % length || bytes / length > UINT32_MAX : bytes != 0) return;
        ArraySnapshot(parameter, data, bytes, length ? static_cast<uint32_t>(bytes / length) : 0u, limit);
    }
}

void Profiler::Enter(ManagedMethod* method, COR_PRF_ELT_INFO information,
    COR_PRF_FUNCTION_ARGUMENT_INFO* legacyArguments)
{
    CallbackScope scope(bridge_);
    auto frame = ManagedFrames.Push(method);
    if (!frame) { bridge_.status(static_cast<uint32_t>(ManagedState::Failed)); return; }
    auto limit = bridge_.bufferLimit(method->api);
    frame->bufferLimit = limit;
    if (!active_ || (!limit && !method->nativeDelegate) || scope.Reentered()) return;
    ManagedFrames.payload.clear();
    std::array<uint64_t, MaximumArguments> arguments{};
    alignas(16) std::byte storage[sizeof(COR_PRF_FUNCTION_ARGUMENT_INFO) +
        ArgumentRangeBufferCount * sizeof(COR_PRF_FUNCTION_ARGUMENT_RANGE)]{};
    auto ranges = legacyArguments ? legacyArguments : reinterpret_cast<COR_PRF_FUNCTION_ARGUMENT_INFO*>(storage);
    ULONG size = sizeof(storage);
    COR_PRF_FRAME_INFO frameInformation = 0;
    auto read = legacyArguments ? S_OK : modernInformation_ ? modernInformation_->GetFunctionEnter3Info(
        method->function, information, &frameInformation, &size, ranges) : E_FAIL;
    if (SUCCEEDED(read))
    {
        auto count = std::min<uint32_t>(ranges->numRanges, MaximumArguments);

        // Delegate construction exposes private native targets even when managed recording is filtered.
        if (method->nativeDelegate && count && ranges->ranges[0].length >= sizeof(uintptr_t))
        {
            uintptr_t address = 0;
            if (SafeRead(&address, reinterpret_cast<const void*>(ranges->ranges[0].startAddress), sizeof(address)))
                bridge_.nativeDelegate(address);
        }
        if (!limit) return;

        // Unknown value-type sizes retain raw regions without suppressing other parameters' decoded outputs.
        bool decoded = ranges->numRanges == method->arguments.size();
        if (decoded)
        {
            for (uint32_t index = 0; index < count; ++index)
                decoded = decoded && ranges->ranges[index].length >= method->arguments[index].bytes;
        }
        for (uint32_t index = 0; index < count; ++index)
        {
            const auto& range = ranges->ranges[index];
            auto address = reinterpret_cast<const void*>(range.startAddress);
            if (decoded)
            {
                const auto& type = method->arguments[index];
                auto bytes = type.bytes ? type.bytes : range.length;
                if (type.bytes && type.bytes <= sizeof(uint64_t)) SafeRead(&arguments[index], address, type.bytes);
                Snapshot(index, type.bytes && type.bytes <= sizeof(uint64_t) ? ValueKind::Scalar : ValueKind::Bytes,
                    address, bytes, limit);
                ObjectSnapshot(index, type, arguments[index], limit);
                if (arguments[index] && (type.byReference || type.arrayRank))
                {
                    frame->outputMask |= uint32_t{1} << index;
                    frame->outputValues[index] = arguments[index];
                }
            }
            else Snapshot(index, ValueKind::Bytes, address, range.length, limit);
        }
    }
    else
    {
        if (!limit) return;
        for (uint32_t index = 0; index < std::min<size_t>(method->arguments.size(), MaximumArguments); ++index)
            Unavailable(index, method->arguments[index].bytes);
    }
    frame->constructed = bridge_.begin(&frame->state, method->api, arguments.data(),
        static_cast<uint32_t>(std::min<size_t>(method->arguments.size(), MaximumArguments)),
        ManagedFrames.payload.data(), static_cast<uint32_t>(ManagedFrames.payload.size()));
}

void Profiler::CaptureAttached(ManagedMethod* method, const ManagedArgument* regions, ManagedCallPhase phase)
{
    CallbackScope scope(bridge_);
    auto count = method->instrumentedArguments;
    auto buffer = [&](uint32_t parameter, const ManagedArgument& region, const ManagedType* type, uint32_t limit)
    {
        if (region.elementBytes && (!type || !type->elementBytes))
            ArraySnapshot(parameter, region.buffer, region.bufferBytes,
                static_cast<uint32_t>(region.elementBytes), limit);
        else if (region.buffer)
            Snapshot(parameter, type && type->element == ELEMENT_TYPE_STRING ? ValueKind::Utf16 : ValueKind::Bytes,
                region.buffer, region.bufferBytes, limit);
    };
    if (phase == ManagedCallPhase::Enter)
    {
        auto frame = ManagedFrames.Push(method);
        if (!frame) { Failure(); return; }
        frame->bufferLimit = bridge_.bufferLimit(method->api);
        if (!active_ || !frame->bufferLimit || scope.Reentered()) return;
        ManagedFrames.payload.clear();
        std::array<uint64_t, MaximumArguments> arguments{};
        for (uint32_t index = 0; index < count; ++index)
        {
            const auto& region = regions[index];
            if (region.bytes <= sizeof(uint64_t)) SafeRead(&arguments[index], region.address,
                static_cast<size_t>(region.bytes));
            Snapshot(index, region.bytes <= sizeof(uint64_t) ? ValueKind::Scalar : ValueKind::Bytes,
                region.address, region.bytes, frame->bufferLimit);
            if (region.indirect)
                Snapshot(index, ValueKind::Bytes, region.indirect, region.indirectBytes, frame->bufferLimit);
            buffer(index, region, index < method->arguments.size() ? &method->arguments[index] : nullptr,
                frame->bufferLimit);
        }
        frame->constructed = bridge_.begin(&frame->state, method->api, arguments.data(), count,
            ManagedFrames.payload.data(), static_cast<uint32_t>(ManagedFrames.payload.size()));
        return;
    }
    if (ManagedFrames.overflow) { --ManagedFrames.overflow; return; }
    auto index = ManagedFrames.FindDepth(method);
    if (!index) return;
    ManagedFrames.payload.clear();
    while (ManagedFrames.depth > index) EndTop(Failed | Unwound);
    auto& frame = ManagedFrames.At(index - 1);
    uint64_t result = 0;
    if (phase == ManagedCallPhase::Leave && frame.constructed && active_)
    {
        // The IL supplies current output addresses, including buffers moved or replaced during the call.
        for (uint32_t parameter = 0; parameter < count; ++parameter)
        {
            const auto& region = regions[parameter];
            if (region.indirect)
                Snapshot(parameter, ValueKind::Bytes, region.indirect, region.indirectBytes, frame.bufferLimit);
            if (region.indirect || region.elementBytes)
                buffer(parameter, region,
                    parameter < method->arguments.size() ? &method->arguments[parameter] : nullptr, frame.bufferLimit);
        }
        if (method->result.element != ELEMENT_TYPE_VOID)
        {
            const auto& region = regions[count];
            SafeRead(&result, region.address, static_cast<size_t>(std::min<uint64_t>(region.bytes, sizeof(result))));
            Snapshot(UINT32_MAX, region.bytes <= sizeof(uint64_t) ? ValueKind::Scalar : ValueKind::Bytes,
                region.address, region.bytes, frame.bufferLimit);
            if (region.indirect)
                Snapshot(UINT32_MAX, ValueKind::Bytes, region.indirect, region.indirectBytes, frame.bufferLimit);
            buffer(UINT32_MAX, region, &method->result, frame.bufferLimit);
        }
    }
    EndTop(phase == ManagedCallPhase::Tailcall ? Continuation : 0u, result);
}

void WINAPI AttachedManagedCall(ManagedMethod* method, const ManagedArgument* arguments, ManagedCallPhase phase)
{
    auto owner = static_cast<Profiler*>(method->owner);
    auto depth = ManagedFrames.depth;
    try { owner->CaptureAttached(method, arguments, phase); }
    catch (...)
    {
        if (phase != ManagedCallPhase::Enter) owner->FailedLeave(method);
        else
        {
            if (ManagedFrames.depth == depth) ++ManagedFrames.overflow;
            owner->Failure();
        }
    }
}

void Profiler::EndTop(uint32_t flags, uint64_t result)
{
    if (!ManagedFrames.depth) return;
    auto& frame = ManagedFrames.At(--ManagedFrames.depth);
    if (frame.constructed)
    {
        auto owner = static_cast<Profiler*>(frame.method->owner);
        owner->bridge_.end(&frame.state, result, flags, ManagedFrames.payload.data(),
            static_cast<uint32_t>(ManagedFrames.payload.size()));
        frame.constructed = 0;
    }
}

void Profiler::Leave(ManagedMethod* method, COR_PRF_ELT_INFO information, uint32_t flags,
    COR_PRF_FUNCTION_ARGUMENT_RANGE* legacyResult)
{
    CallbackScope scope(bridge_);
    if (ManagedFrames.overflow) { --ManagedFrames.overflow; return; }
    if (!ManagedFrames.depth) return;
    ManagedFrames.payload.clear();
    auto index = ManagedFrames.FindDepth(method);
    if (!index) return;
    while (ManagedFrames.depth > index) EndTop(Failed | Unwound);
    uint64_t result = 0;
    if (!flags && ManagedFrames.At(index - 1).constructed && active_)
    {
        // GC notifications update mutable argument addresses before the runtime resumes this callback.
        auto& frame = ManagedFrames.At(index - 1);
        for (uint32_t parameter = 0; parameter < MaximumArguments; ++parameter)
        {
            if (!(frame.outputMask & (uint32_t{1} << parameter))) continue;
            if (frame.outputValues[parameter])
                ObjectSnapshot(parameter, method->arguments[parameter], frame.outputValues[parameter],
                    frame.bufferLimit);
            else Unavailable(parameter, method->arguments[parameter].bytes);
        }
        COR_PRF_FRAME_INFO frameInformation = 0;
        COR_PRF_FUNCTION_ARGUMENT_RANGE range{};
        auto read = legacyResult ? S_OK : modernInformation_ ? modernInformation_->GetFunctionLeave3Info(
            method->function, information, &frameInformation, &range) : E_FAIL;
        if (legacyResult) range = *legacyResult;
        if (SUCCEEDED(read) && range.length)
        {
            auto limit = ManagedFrames.At(index - 1).bufferLimit;
            SafeRead(&result, reinterpret_cast<const void*>(range.startAddress),
                std::min<size_t>(range.length, sizeof(result)));
            Snapshot(UINT32_MAX, range.length <= sizeof(uint64_t) ? ValueKind::Scalar : ValueKind::Bytes,
                reinterpret_cast<const void*>(range.startAddress), range.length, limit);
            ObjectSnapshot(UINT32_MAX, method->result, result, limit);
        }
        else if (FAILED(read) && method->result.element != ELEMENT_TYPE_VOID)
        {
            Unavailable(UINT32_MAX, method->result.bytes);
        }
    }
    EndTop(flags, result);
}

template<class Visitor> void Profiler::VisitOutputFrames(Visitor visitor)
{
    // GC pauses managed callbacks; the list lock protects concurrent native TLS teardown.
    AcquireSRWLockExclusive(&ManagedThreadsLock);
    for (auto thread = ManagedThreads; thread; thread = thread->next)
        for (uint32_t index = 0; index < thread->depth; ++index)
        {
            auto& frame = thread->At(index);
            if (frame.constructed && frame.outputMask && frame.method->owner == this) visitor(frame);
        }
    ReleaseSRWLockExclusive(&ManagedThreadsLock);
}

HRESULT Profiler::GarbageCollectionStarted(int count, BOOL collected[], COR_PRF_GC_REASON)
{
    CallbackScope scope(bridge_);
    VisitOutputFrames([](ManagedFrame& frame) { frame.pendingMoveMask = frame.outputMask; });
    try
    {
        ULONG rangeCount = 0;
        if (FAILED(information_->GetGenerationBounds(0, &rangeCount, nullptr))) return S_OK;
        std::vector<COR_PRF_GC_GENERATION_RANGE> ranges(rangeCount);
        if (FAILED(information_->GetGenerationBounds(rangeCount, &rangeCount, ranges.data()))) return S_OK;
        VisitOutputFrames([&](ManagedFrame& frame)
        {
            frame.pendingMoveMask = 0;
            for (uint32_t parameter = 0; parameter < MaximumArguments; ++parameter)
            {
                auto bit = uint32_t{1} << parameter;
                if (!(frame.outputMask & bit)) continue;
                auto value = frame.outputValues[parameter];
                for (const auto& range : ranges)
                {
                    auto generation = std::min(static_cast<int>(range.generation), count - 1);
                    if (generation < 0 || !collected[generation] || value < range.rangeStart ||
                        value - range.rangeStart >= range.rangeLength) continue;
                    frame.pendingMoveMask |= bit;
                    break;
                }
            }
        });
    }
    catch (...) { bridge_.status(2); }
    return S_OK;
}

template<class Size> HRESULT Profiler::RelocateReferences(ULONG count, ObjectID before[], ObjectID after[],
    Size bytes[])
{
    CallbackScope scope(bridge_);
    struct Range { uint64_t before, after, bytes; };
    try
    {
        // Search address ranges once per tracked argument rather than scanning each moved object.
        std::vector<Range> ranges;
        ranges.reserve(count);
        for (ULONG index = 0; index < count; ++index) ranges.push_back({before[index], after[index], bytes[index]});
        std::sort(ranges.begin(), ranges.end(), [](const Range& left, const Range& right)
        {
            return left.before < right.before;
        });
        VisitOutputFrames([&](ManagedFrame& frame)
        {
            for (uint32_t parameter = 0; parameter < MaximumArguments; ++parameter)
            {
                auto bit = uint32_t{1} << parameter;
                if (!(frame.pendingMoveMask & bit)) continue;
                auto value = frame.outputValues[parameter];
                auto range = std::upper_bound(ranges.begin(), ranges.end(), value,
                    [](uint64_t address, const Range& item) { return address < item.before; });
                if (range == ranges.begin()) continue;
                --range;
                if (value - range->before >= range->bytes) continue;
                frame.outputValues[parameter] = range->after + (value - range->before);
                frame.pendingMoveMask &= ~bit;
            }
        });
    }
    catch (...) { bridge_.status(2); }
    return S_OK;
}

HRESULT Profiler::GarbageCollectionFinished()
{
    CallbackScope scope(bridge_);
    VisitOutputFrames([](ManagedFrame& frame)
    {
        // Unreported objects were reclaimed; their addresses must never be read again.
        for (uint32_t parameter = 0; parameter < MaximumArguments; ++parameter)
            if (frame.pendingMoveMask & (uint32_t{1} << parameter)) frame.outputValues[parameter] = 0;
        frame.pendingMoveMask = 0;
    });
    return S_OK;
}

HRESULT Profiler::ExceptionUnwindFunctionLeave()
{
    CallbackScope scope(bridge_);
    if (ManagedFrames.unwinds.empty()) return S_OK;
    auto [owner, function] = ManagedFrames.unwinds.back();
    ManagedFrames.unwinds.pop_back();
    if (owner != this || ManagedFrames.overflow) return S_OK;
    auto index = ManagedFrames.depth;
    ModuleID module = 0;
    mdToken token = 0;
    ClassID type = 0;
    if (attached_) information_->GetFunctionInfo(function, &type, &module, &token);
    while (index)
    {
        auto method = ManagedFrames.At(index - 1).method;
        if (method->owner == this && (attached_ ? method->module == module && method->token == token :
            method->function == function)) break;
        --index;
    }
    if (index)
    {
        ManagedFrames.payload.clear();
        while (ManagedFrames.depth >= index) EndTop(Failed | Unwound);
    }
    return S_OK;
}

class ProfilerFactory final : public IClassFactory
{
public:
    ProfilerFactory() { ++ProfilerObjects; }
    ~ProfilerFactory() { --ProfilerObjects; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** result) override
    {
        if (!result) return E_POINTER;
        *result = nullptr;
        if (iid != IID_IUnknown && iid != IID_IClassFactory) return E_NOINTERFACE;
        *result = this;
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        auto remaining = --references_;
        if (!remaining) delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** result) override
    {
        if (outer) return CLASS_E_NOAGGREGATION;
        auto profiler = new (std::nothrow) Profiler;
        if (!profiler) return E_OUTOFMEMORY;
        auto status = profiler->QueryInterface(iid, result);
        profiler->Release();
        return status;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override
    {
        if (lock) ++ProfilerObjects;
        else --ProfilerObjects;
        return S_OK;
    }
private:
    std::atomic<ULONG> references_ = 1;
};
}

static void RecordManagedEnter(Detourist::ManagedMethod* method, COR_PRF_ELT_INFO information,
    COR_PRF_FUNCTION_ARGUMENT_INFO* arguments = nullptr)
{
    auto profiler = static_cast<Detourist::Profiler*>(method->owner);
    auto depth = Detourist::ManagedFrames.depth;
    try { profiler->Enter(method, information, arguments); }
    catch (...)
    {
        if (depth == Detourist::ManagedFrames.depth) ++Detourist::ManagedFrames.overflow;
        profiler->Failure();
    }
}

static void RecordManagedLeave(Detourist::ManagedMethod* method, COR_PRF_ELT_INFO information, uint32_t flags,
    COR_PRF_FUNCTION_ARGUMENT_RANGE* result = nullptr)
{
    auto profiler = static_cast<Detourist::Profiler*>(method->owner);
    try { profiler->Leave(method, information, flags, result); }
    catch (...) { profiler->FailedLeave(method); }
}

extern "C" void DetouristManagedEnter(Detourist::ManagedMethod* method, COR_PRF_ELT_INFO information)
{
    RecordManagedEnter(method, information);
}
extern "C" void DetouristManagedLeave(Detourist::ManagedMethod* method, COR_PRF_ELT_INFO information)
{
    RecordManagedLeave(method, information, 0);
}
extern "C" void DetouristManagedTailcall(Detourist::ManagedMethod* method, COR_PRF_ELT_INFO information)
{
    RecordManagedLeave(method, information, Detourist::Continuation);
}

extern "C" void DetouristManagedEnter2(FunctionID, UINT_PTR clientData, COR_PRF_FRAME_INFO,
    COR_PRF_FUNCTION_ARGUMENT_INFO* arguments)
{
    RecordManagedEnter(reinterpret_cast<Detourist::ManagedMethod*>(clientData), 0, arguments);
}
extern "C" void DetouristManagedLeave2(FunctionID, UINT_PTR clientData, COR_PRF_FRAME_INFO,
    COR_PRF_FUNCTION_ARGUMENT_RANGE* result)
{
    RecordManagedLeave(reinterpret_cast<Detourist::ManagedMethod*>(clientData), 0, 0, result);
}
extern "C" void DetouristManagedTailcall2(FunctionID, UINT_PTR clientData, COR_PRF_FRAME_INFO)
{
    RecordManagedLeave(reinterpret_cast<Detourist::ManagedMethod*>(clientData), 0, Detourist::Continuation);
}

STDAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void** result)
{
    if (clsid != Detourist::ProfilerGuid)
    {
        // Accept only the session identity inherited by this target's CLR activation environment.
        wchar_t text[Detourist::GuidStringCapacity]{};
        GUID expected{};
        auto length = GetEnvironmentVariableW(L"COR_PROFILER", text, static_cast<DWORD>(std::size(text)));
        if (!length || length >= std::size(text) || FAILED(CLSIDFromString(text, &expected)) || clsid != expected)
            return CLASS_E_CLASSNOTAVAILABLE;
    }
    auto factory = new (std::nothrow) Detourist::ProfilerFactory;
    if (!factory) return E_OUTOFMEMORY;
    auto status = factory->QueryInterface(iid, result);
    factory->Release();
    return status;
}

STDAPI DllCanUnloadNow()
{
    return Detourist::ProfilerObjects == 0 ? S_OK : S_FALSE;
}

extern "C" BOOL WINAPI DetouristIsManagedThread()
{
    BOOL found = FALSE;
    AcquireSRWLockShared(&Detourist::RuntimeProfilersLock);
    for (auto runtime = Detourist::RuntimeProfilers; runtime && !found; runtime = runtime->nextRuntime)
        found = runtime->IsCurrentThreadManaged();
    ReleaseSRWLockShared(&Detourist::RuntimeProfilersLock);
    return found;
}
