#pragma once
#include "Transport.h"
#include "CaptureValues.h"
#include "AsyncIo.h"
#include "RpcCapture.h"
#include "ObserverBridge.h"
#include "CaptureTiming.h"
#include <initializer_list>
#include <type_traits>
#include <span>

namespace Detourist
{
extern SRWLOCK CaptureLock;
extern Transport* ActiveTransport;
extern volatile LONG ManagedProfilerState;
[[msvc::no_tls_guard]] extern constinit thread_local bool ObserverActive;
[[msvc::no_tls_guard]] extern constinit thread_local uint64_t ParentCall;
[[msvc::no_tls_guard]] extern constinit thread_local uint32_t CallDepth;
[[msvc::no_tls_guard]] extern constinit thread_local Api CallApi;
[[msvc::no_tls_guard]] extern constinit thread_local uint64_t CallIdentity;
[[msvc::no_tls_guard]] extern constinit thread_local bool FollowingChild;
[[msvc::no_tls_guard]] extern constinit thread_local CaptureClock CaptureTime;
extern uint32_t InstalledNativeCount;
extern uint32_t AvailableNativeCount;
extern uint32_t NativeExportCount;
extern char UnknownNativeExports[UnknownNativeExportsCapacity];
extern volatile LONG ProcessShuttingDown;
extern uint32_t InstalledWin32Count;
extern uint32_t AvailableWin32Count;
extern uint32_t InstalledComCount;
extern uint32_t InstalledExportCount;
extern bool BroadHooks;

struct Call
{
    Transport* transport = nullptr;
    const CatalogPlan* exportPlan = nullptr;
    RpcCaptureState* rpc = nullptr;
    uint64_t returnBuffer = 0;
    Event event{};
    CaptureObservation observation;
    int64_t invocationStarted = 0;
    bool invocationRunning = false;
    uint64_t previousParent = 0;
    uint64_t previousIdentity = 0;
    uint32_t previousDepth = 0;
    Api previousApi = Api::Count;
    uint64_t captureLimits[MaximumArguments]{};
    MruCaptureState mru;
    AsyncIoRole asyncRole = AsyncIoRole::None;
    uint32_t callbackParameter = UINT32_MAX;
    uint64_t callbackArgument = 0;
    uint32_t requestedBytes = 0;
    uint32_t initializedOutputs = 0;
    bool skipped = false;
    bool finished = false;
    bool record = false;
    bool mruOnly = false;
    bool internalRuntime = false;
    Call(Api api, std::initializer_list<uint64_t> arguments, void* caller);
    Call(Api api, std::span<const uint64_t> arguments, void* caller,
        std::span<const std::byte> payload = {}, uint32_t flags = 0, uint64_t returnedBuffer = 0,
        RpcCaptureState* rpc = nullptr);
    ~Call();
    void Finish(uint64_t result, DWORD error, std::span<const std::byte> payload = {});
    void Break(bool leaving);
    void ReleaseForContinuation();
    void BeginInvocation();
    void EndInvocation();
    template<class Function> decltype(auto) Invoke(Function&& function)
    {
        BeginInvocation();
        struct Completion
        {
            Call& call;
            ~Completion() { call.EndInvocation(); }
        } completion{*this};
        return function();
    }
    uint64_t InvocationArgument(uint32_t index) const
    {
        return index == callbackParameter ? callbackArgument : event.arguments[index];
    }
};

extern "C" __declspec(dllexport) uint64_t WINAPI DetouristAsyncCallback(uint64_t identity, uint64_t callback,
    uint32_t kind, uint64_t* original);

// Holds a created child's initial thread until the collector has attempted attachment.
class ChildLaunch
{
public:
    explicit ChildLaunch(Call& call);
    ~ChildLaunch() { Complete(false); }
    void Complete(bool success);
private:
    Call& call_;
    ChildRequest* request_ = nullptr;
    uint32_t flagIndex_ = 0, flags_ = 0;
    bool native_ = false;
};

struct HookDefinition { Api api; void** original; void* observer; };
void AddNativeHooks(std::vector<HookDefinition>& hooks);
#ifndef _WIN64
void* PrepareNativeContinuation(Api api, void** original, const ExportSignature& signature);
#endif
FARPROC NativeInteropObserver(FARPROC function);
FARPROC NativeInteropTarget(FARPROC function);
FARPROC Win32uInteropObserver(FARPROC function);
FARPROC Win32InteropObserver(HMODULE module, LPCSTR name, FARPROC function, bool aliasesOnly);
void AddWin32Hooks(std::vector<HookDefinition>& hooks);
void AddUnpatchedWin32Hooks(std::vector<HookDefinition>& hooks);
void AddWin32uHooks(std::vector<HookDefinition>& hooks);
void AddExportHooks(std::vector<HookDefinition>& hooks, const CatalogView& catalog);
bool ExportEntryPatchable(void* address);
void ActivateExportHooks();
FARPROC ExportInteropObserver(HMODULE module, LPCSTR name, FARPROC function);
FARPROC ExportInteropTarget(FARPROC function);
void ForgetExportModule(HMODULE module, size_t size);
void DiscoverCatalogInterfaces(Call& call, uint64_t result, bool leaving);

void AddModuleHooks(std::vector<HookDefinition>& hooks);
void StartModuleNotifications();
void EnableModuleRefresh();
void PublishHookCoverage(SharedHeader& header);
void ProcessModuleChanges();
void BindModuleHistory(SharedHeader* header);
uint64_t RefreshHooks(Transport* transport, bool includeNative = false);
void InvalidateHooks(HMODULE module, size_t size);

struct NativeCallResult;
struct ComMethodObserver
{
    Api api;
    void* entry;
    ExportSignature signature;
    uint32_t argumentCount;
};
void AddComHooks(std::vector<HookDefinition>& hooks, HMODULE module);
void ForgetComModule(HMODULE module, size_t size);
void AddComMethodHooks(void** table, const GUID& iid, const CatalogView& catalog, const CatalogInterface* contract,
    std::span<const ComMethodObserver* const> observers);
void ForgetComMethodModule(HMODULE module, size_t size);
void InvokeComMethodObserver(const ComMethodObserver& observer, void* original, uint32_t slot, uint64_t caller,
    const uint64_t* arguments, NativeCallResult* result, uint32_t argumentSlots = 0);
void EmitCom(Call& call, Slot* slot, bool leaving);
void DiscoverComOutput(HRESULT result, uint64_t output, const IID* iid);
void DiscoverWin32ComOutput(Api api, uint64_t result, const uint64_t* arguments);

void AddStackHooks(std::vector<HookDefinition>& hooks);
bool IsStackHook(void* observer);
void CaptureCallStack(Call& call, Slot* slot);
void InvalidateStackImageCache() noexcept;
void DetachObserverThread() noexcept;

struct ExportCallInfo
{
    const CatalogPlan* plan = nullptr;
    uint64_t categoryMask = CategoryMask(ApiCategory::Unclassified);
    uint64_t nameHash = 0;
    AsyncIoRole asyncRole = AsyncIoRole::None;
};
ExportCallInfo ResolveExportCall(Api api, const Transport& transport);
bool PublishExportMetadata(Call& call);
HMODULE ResolveHookModule(const wchar_t* name);
void CaptureBuiltinParameters(Call& call, Slot* slot, bool leaving);
bool CaptureRpcMarshalValues(Call& call, Slot* slot, bool leaving);
void EmitWin32u(Call& call, Slot* slot, bool leaving);
bool IsWin32uFailure(Api api, uint64_t result);
bool NativeThreadReady();
void WINAPI ObserveNativeDelegate(uintptr_t address);
bool EnableNativeGateways(HMODULE runtime);
void DisableNativeGateways();
bool PublishManagedApiMetadata(Api api, Transport* transport);
void RefreshManagedApiCategories();
uint64_t ManagedApiCategoryMask(Api api);
uint64_t ManagedApiNameHash(Api api);
void EmitNative(Call& call, Slot* slot, bool leaving);
bool NativeStackSafe(uint64_t caller = 0);
DWORD NativeThreadStatus();
void RestoreNativeThreadStatus(DWORD status);

// Observer work must leave the application's thread state intact, including nested observations.
class ObserverScope
{
public:
    ObserverScope() { ObserverActive = true; }
    ~ObserverScope()
    {
        ObserverActive = previous_;
        SetLastError(error_);
        RestoreNativeThreadStatus(status_);
    }
    ObserverScope(const ObserverScope&) = delete;
    ObserverScope& operator=(const ObserverScope&) = delete;
private:
    DWORD error_ = GetLastError();
    DWORD status_ = NativeThreadStatus();
    bool previous_ = ObserverActive;
};

uint64_t InstallHooks(Transport& transport);
void Emit(Call& call, bool leaving, std::span<const std::byte> payload = {});
bool IsFailure(Api api, uint64_t result);

template<class T> uint64_t Bits(T value)
{
    if constexpr (std::is_pointer_v<T>) return reinterpret_cast<uint64_t>(value);
    else if constexpr (std::is_integral_v<T> || std::is_enum_v<T>) return static_cast<uint64_t>(value);
    else
    {
        static_assert(sizeof(T) <= sizeof(uint64_t) && std::is_trivially_copyable_v<T>);
        uint64_t bits = 0;
        memcpy(&bits, &value, sizeof(value));
        return bits;
    }
}
template<class T> T Argument(const Call& call, uint32_t index)
{
    auto argument = call.InvocationArgument(index);
    if constexpr (std::is_pointer_v<T>) return reinterpret_cast<T>(argument);
    else if constexpr (std::is_integral_v<T> || std::is_enum_v<T>) return static_cast<T>(argument);
    else
    {
        static_assert(sizeof(T) <= sizeof(uint64_t) && std::is_trivially_copyable_v<T>);
        T value{};
        memcpy(&value, &argument, sizeof(value));
        return value;
    }
}
}
