#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <array>
#include <string_view>
#include "ApiCategories.h"

namespace Detourist
{
#pragma warning(push)
#pragma warning(disable: 4995)
constexpr uint32_t ProtocolMagic = 0x52555444;
constexpr uint32_t ProtocolVersion = 30;
constexpr uint32_t InlineSlotPayloadBytes = 3712;
constexpr uint32_t MaximumTransportCapacity = 2048;
constexpr uint32_t MaximumStack = 48;
constexpr uint32_t MaximumArguments = 32;
constexpr uint32_t RawArgumentCount = 20;
constexpr uint32_t MinimumBufferLimit = 16;
constexpr uint32_t DefaultBufferLimit = 1024;
constexpr uint32_t MaximumBufferLimit = 65536;
constexpr uint32_t TransportBudget = 16 * 1024 * 1024;
constexpr uint32_t PoolIndexMask = 0xFFFF;
constexpr uint32_t MaximumExcludedApis = 1024;
constexpr uint32_t ApiExclusionSlots = 2048;
constexpr uint32_t ModuleHistoryCapacity = 512;
constexpr uint32_t ThreadIdCapacity = 4096;
constexpr uint32_t MaximumModulePath = 1024;
constexpr uint32_t AsyncIoCapacity = 4096;
constexpr uint32_t AsyncIoBuckets = 1024;
constexpr size_t MaximumApiModuleBytes = 128;
constexpr size_t MaximumApiNameBytes = 384;
constexpr size_t MaximumApiParametersChars = 512;
constexpr size_t MaximumApiLayoutBytes = 1024;
constexpr size_t CatalogMappingCapacity = 96;
constexpr size_t UnknownNativeExportsCapacity = 2048;
constexpr size_t ChildRequestCapacity = 32;
constexpr size_t RpcAsyncCapacity = 128;
constexpr uint16_t RpcMaxValueNodes = 128;
constexpr size_t RpcMaxArrays = 64;
constexpr uint32_t CacheLineBytes = 64;
constexpr uint64_t Fnv1aOffsetBasis64 = 14695981039346656037ull;
constexpr uint64_t Fnv1aPrime64 = 1099511628211ull;
constexpr uint32_t Fnv1aOffsetBasis32 = 2166136261u;
constexpr uint32_t Fnv1aPrime32 = 16777619u;

inline uint64_t ApiNameHash(std::string_view name)
{
    uint64_t hash = Fnv1aOffsetBasis64;
    for (const auto character : name) hash = (hash ^ static_cast<uint8_t>(character)) * Fnv1aPrime64;
    return hash > 1 ? hash : hash + 2;
}

constexpr uint32_t PoolIndex(LONGLONG head) { return static_cast<uint32_t>(head) & PoolIndexMask; }
constexpr LONGLONG NextPoolHead(LONGLONG head, uint32_t index)
{
    return static_cast<LONGLONG>(((static_cast<uint64_t>(head) + PoolIndexMask + 1) &
        ~uint64_t{PoolIndexMask}) | index);
}

inline LONGLONG ReadShared64(volatile LONGLONG& value)
{
    // Aligned 64-bit loads are atomic on 64-bit targets; WOW64 needs an interlocked read.
#ifdef _WIN64
    return ReadAcquire64(&value);
#else
    return InterlockedCompareExchange64(&value, 0, 0);
#endif
}

enum class Api : uint32_t
{
#define CORE_API(name, failure) name,
#include "CoreCatalog.inc"
#undef CORE_API
#define NATIVE_API(name, ...) name,
#include "NativeCatalog.inc"
#undef NATIVE_API
#define WIN32_BINDING(name) name,
#include "Win32Bindings.h"
#undef WIN32_BINDING
#define COM_EXPORT(name) name,
#define COM_METHOD(id, owner, slot, ...) id,
#include "ComCatalog.inc"
#undef COM_EXPORT
#undef COM_METHOD
#define WIN32U_API(name, ...) name,
#define WIN32U_UNSUPPORTED(name) name,
#include "Win32uCatalog.inc"
#undef WIN32U_UNSUPPORTED
#undef WIN32U_API
    Count
};

struct CatalogPlan;
struct ApiDefinition
{
    Api id;
    const char* module;
    const char* name;
    const wchar_t* parameters;
    uint32_t argumentCount;
    uint32_t hookFlags;
    const char* nativeName;
    const CatalogPlan* plan;
    const uint32_t* resultSuccesses;
};
constexpr uint32_t HookContinuation = 1, HookProcessTermination = 2, HookDirectInterop = 4, HookWait = 8;
constexpr uint32_t HookCompleteOutput = 16;
constexpr uint32_t NativeHookFlagsMask = HookContinuation | HookProcessTermination | HookDirectInterop | HookWait;
constexpr uint32_t AllHookFlagsMask = NativeHookFlagsMask | HookCompleteOutput;

extern ApiDefinition ApiDefinitions[static_cast<uint32_t>(Api::Count)];
constexpr uint32_t NativeApiStart = 0
#define CORE_API(name, failure) + 1
#include "CoreCatalog.inc"
#undef CORE_API
;
constexpr uint32_t NativeApiEnd = NativeApiStart
#define NATIVE_API(name, ...) + 1
#include "NativeCatalog.inc"
#undef NATIVE_API
;
constexpr uint32_t Win32ApiStart = NativeApiEnd;
constexpr uint32_t Win32ApiEnd = Win32ApiStart
#define WIN32_BINDING(name) + 1
#include "Win32Bindings.h"
#undef WIN32_BINDING
;
constexpr uint32_t ComApiStart = Win32ApiEnd;
constexpr uint32_t ComApiEnd = ComApiStart
#define COM_EXPORT(name) + 1
#define COM_METHOD(id, owner, slot, ...) + 1
#include "ComCatalog.inc"
#undef COM_EXPORT
#undef COM_METHOD
;
constexpr uint32_t Win32uApiStart = ComApiEnd;
constexpr uint32_t Win32uApiEnd = static_cast<uint32_t>(Api::Count);
constexpr uint32_t ManagedApiStart = 0x40000000;
constexpr uint32_t ManagedDebuggerApiStart = 0x48000000;
constexpr uint32_t InterfaceApiStart = 0x50000000;
constexpr uint32_t FixedInterfaceApiStart = InterfaceApiStart + 0x08000000;
constexpr uint32_t SyscallApiStart = 0x60000000;
constexpr uint32_t ExportApiStart = 0x70000000;
constexpr uint32_t FixedExportApiStart = ExportApiStart + 0x08000000;
constexpr uint32_t RpcMarshalApiStart = ExportApiStart + 0x0C000000;
constexpr uint32_t ExportApiEnd = 0x80000000;
constexpr uint64_t NativeApis = uint64_t{1} << NativeApiStart;
constexpr uint64_t Win32Apis = uint64_t{1} << 19;
constexpr uint64_t ComApis = uint64_t{1} << 20;
constexpr uint64_t ManagedApis = uint64_t{1} << 21;
constexpr uint64_t Win32uApis = uint64_t{1} << 22;
constexpr uint64_t DirectSyscalls = uint64_t{1} << 23;
constexpr uint64_t AllApis = (DirectSyscalls << 1) - 1;

// Sources and functional categories share one atomic capture configuration.
constexpr uint64_t CaptureFilters(uint64_t sources, uint64_t categories)
{
    return (sources & AllApis) | ((categories & AllCategories) << 32);
}
inline bool FilterEnabled(uint64_t filters, uint64_t source, uint64_t category)
{
    return (filters & source) && ((filters >> 32) & category);
}
constexpr bool IsNativeApi(Api api)
{
    return static_cast<uint32_t>(api) >= NativeApiStart && static_cast<uint32_t>(api) < NativeApiEnd;
}
constexpr bool IsWin32Api(Api api)
{
    return static_cast<uint32_t>(api) >= Win32ApiStart && static_cast<uint32_t>(api) < Win32ApiEnd;
}
constexpr bool IsComApi(Api api)
{
    return static_cast<uint32_t>(api) >= ComApiStart && static_cast<uint32_t>(api) < ComApiEnd;
}
constexpr bool IsWin32uApi(Api api)
{
    return static_cast<uint32_t>(api) >= Win32uApiStart && static_cast<uint32_t>(api) < Win32uApiEnd;
}
constexpr bool IsManagedApi(Api api)
{
    return static_cast<uint32_t>(api) >= ManagedApiStart && static_cast<uint32_t>(api) < InterfaceApiStart;
}
constexpr bool IsInterfaceApi(Api api)
{
    return static_cast<uint32_t>(api) >= InterfaceApiStart && static_cast<uint32_t>(api) < SyscallApiStart;
}
constexpr bool IsSyscallApi(Api api)
{
    return static_cast<uint32_t>(api) >= SyscallApiStart && static_cast<uint32_t>(api) < ExportApiStart;
}
constexpr bool IsExportApi(Api api)
{
    return static_cast<uint32_t>(api) >= ExportApiStart && static_cast<uint32_t>(api) < ExportApiEnd;
}
constexpr bool IsDynamicApi(Api api)
{
    return IsManagedApi(api) || IsInterfaceApi(api) || IsSyscallApi(api) || IsExportApi(api);
}
constexpr uint64_t ApiMask(Api api)
{
    auto index = static_cast<uint32_t>(api);
    if (index < NativeApiStart) return uint64_t{1} << index;
    if (IsNativeApi(api)) return NativeApis;
    if (IsWin32Api(api)) return Win32Apis;
    if (IsComApi(api) || IsInterfaceApi(api)) return ComApis;
    if (IsWin32uApi(api)) return Win32uApis;
    if (IsSyscallApi(api)) return DirectSyscalls;
    if (IsExportApi(api)) return Win32Apis;
    return IsManagedApi(api) ? ManagedApis : 0;
}
inline constexpr bool NativeStatusResults[] =
{
#define NATIVE_API(name, status, ...) status,
#include "NativeCatalog.inc"
#undef NATIVE_API
};
constexpr bool NativeReturnsStatus(Api api)
{
    return IsNativeApi(api) && NativeStatusResults[static_cast<uint32_t>(api) - NativeApiStart];
}

enum class EventKind : uint32_t
{
    Enter = 1, Leave, Child, Diagnostic, ApiMetadata, ApiLayout, ModuleLoad, ModuleUnload, AsyncCompletion, Completed
};
struct DynamicApiMetadata
{
    uint32_t argumentCount;
    ApiCategory category;
    char module[MaximumApiModuleBytes];
    char name[MaximumApiNameBytes];
    wchar_t parameters[MaximumApiParametersChars];
    char layout[MaximumApiLayoutBytes];
};
struct ApiLayoutFragment
{
    uint32_t offset;
    uint32_t totalBytes;
};
enum class ValueKind : uint32_t
{
    Bytes, Utf16, Scalar, FindData, ProcessInformation, Stack, ObjectAttributes, IoStatus, SafeArray, SafeArrayData,
    PropertyVector, PropertyVectorData, ManagedArray, AutomationLink, PropertyClipboard, RpcCall, RpcValue
};
// ManagedArray stores its element count and byte stride in the low and high 32-bit halves of originalBytes.
// Automation array snapshots retain their VARTYPE in the upper flag word.
struct AutomationLink
{
    uint32_t parentArray;
    uint32_t element;
    uint32_t childArray;
    uint32_t variantType;
};
// UINT32_MAX identifies the parameter's variant buffer, or a scalar child without an array identity.
static_assert(sizeof(AutomationLink) == 16);
enum ValueFlags : uint32_t
{
    Truncated = 1, Unreadable = 2, Pending = 4, ReferencedData = 8, MemberData = 16, AutomationElement = 32,
    StringArrayElement = 64,
    LdapData = 128, SyncAllData = 256, ReplicaData = 512, NetApiData = 1024, EtwData = 2048, SidData = 4096,
    NetApiBytesData = 8192, SecurityDescriptorData = 16384, AuditData = 32768
};
constexpr uint32_t ValueParameterMask = 0xFFu;
constexpr uint32_t ValueReturnedParameter = 0xFFu;
constexpr uint32_t ValueMemberShift = 8;
constexpr uint32_t ValueMemberMaxOffset = 0x00FFFFFFu;
constexpr uint32_t ValueSubIndexShift = 8;
constexpr uint32_t ValueReplicaShift = 10;
constexpr uint32_t ValueSyncAllShift = 12;
constexpr uint32_t ValueDetailShift = 16;
constexpr uint32_t ValueNibbleMask = 0xFu;
constexpr uint32_t ValueStructuredMask = 0xFFF0u;
constexpr uint32_t PackMemberParameter(uint32_t parameter, size_t offset)
{
    return (static_cast<uint32_t>(offset + 1) << ValueMemberShift) | (parameter & ValueParameterMask);
}
constexpr uint32_t UnpackValueParameter(uint32_t packed) { return packed & ValueParameterMask; }
constexpr uint32_t UnpackMemberOffset(uint32_t packed) { return packed >> ValueMemberShift; }

enum EventFlags : uint32_t
{
    Failed = 1, Skipped = 2, Unwound = 4, AsyncPending = 8, Edited = 16, Continuation = 32,
    StackUnavailable = 64, Syscall = 128, RawArguments = 256, KernelDispatcher = 512,
    OptionalArgumentAbsent = 1024, FormattedArguments = 2048,
    AsyncCompleted = 1u << 18, AsyncCancelled = 1u << 19, DurationMeasured = 1u << 20
};
constexpr uint32_t FormattedArgumentShift = 12;
constexpr uint32_t FormattedArgumentMask = 63u << FormattedArgumentShift;
enum class AgentState : LONG { Starting, Active, Stopping, Stopped, Failed };
enum class InstructionState : LONG { Inactive, Active, Failed, Stopped, Starting, Stopping };
enum class ManagedState : LONG { Inactive, Active, Failed, Attaching };
enum class BootstrapState : LONG { Unarmed, ApcQueued, LoaderReady, Permitted };
enum class ChildRequestState : LONG { Claimed = -1, Idle = 0, Pending = 1, Attaching = 2, Complete = 3, Abandoned = 4 };
enum class ThreadIdState : LONG { Idle, Pending, Processing, Ready };
enum class BreakpointPhase : LONG { Enter, Leave };
enum class BreakpointAction : LONG { Continue, Skip };
enum class ModuleChangeReason : uint32_t { Load = 1, Unload = 2 };
constexpr LONG TransportStopping = 1, TransportStopped = 2;
constexpr LONG CooperativeDebugger = 2;

struct Event
{
    EventKind kind;
    Api api;
    uint64_t callId;
    uint64_t parentId;
    int64_t timestamp;
    int64_t adjustedDuration;
    uint64_t caller;
    uint64_t result;
    uint64_t arguments[MaximumArguments];
    uint32_t processId;
    uint32_t threadId;
    uint32_t depth;
    uint32_t error;
    uint32_t flags;
    uint32_t payloadBytes;
    uint64_t moduleEpoch;
};
static_assert(sizeof(Event) == 344);

struct Value
{
    uint32_t parameter;
    ValueKind kind;
    uint32_t flags;
    uint32_t capturedBytes;
    uint64_t originalBytes;
};
static_assert(sizeof(Value) == 24);

// Cache-line boundaries isolate producer, consumer, and debugger state.
#pragma warning(push)
#pragma warning(disable: 4324)
struct alignas(64) Breakpoint
{
    volatile LONG ownerThread;
    volatile LONG waiting;
    volatile LONG action;
    volatile LONG phase;
    Event event;
};

struct ThreadIdRequest
{
    // States: idle, pending, collector processing, response ready.
    volatile LONG state;
    DWORD error;
    DWORD count;
    DWORD ids[ThreadIdCapacity];
};

struct ChildRequest
{
    volatile LONG state;
    DWORD processId;
    DWORD threadId;
    DWORD error;
    uint32_t suspended;
};

// Creation APIs gate the child's initial thread through their creation flags and report it in process information.
constexpr bool CreatesChild(Api api)
{
    return api == Api::CreateProcessW || api == Api::CreateProcessA || api == Api::CreateProcessAsUserW ||
        api == Api::CreateProcessAsUserA || api == Api::CreateProcessWithLogonW ||
        api == Api::CreateProcessWithTokenW || api == Api::NtCreateUserProcess;
}
constexpr uint32_t ChildFlagsArgument(Api api)
{
    return api == Api::NtCreateUserProcess ? 7 : api == Api::CreateProcessWithTokenW ? 4 :
        api == Api::CreateProcessW || api == Api::CreateProcessA ? 5 : 6;
}
constexpr uint32_t ChildOutputArgument(Api api)
{
    return api == Api::CreateProcessWithTokenW ? 8 : api == Api::CreateProcessW || api == Api::CreateProcessA ? 9 : 10;
}

struct ModuleIdentity
{
    uint32_t timestamp, imageSize, checksum, pdbAge;
    GUID pdb;
    uint16_t machine, flags;
    char pdbName[1024];
    bool operator==(const ModuleIdentity&) const = default;
};
constexpr uint16_t ImageIdentityValid = 1, PdbIdentityValid = 2;
static_assert(sizeof(ModuleIdentity) == 1060);

struct ModuleChange
{
    uint64_t epoch, base, size;
    uint32_t reason, characters;
    ModuleIdentity identity;
    wchar_t path[MaximumModulePath];
};

enum class AsyncIoRole : uint32_t
{
    None, ReadFile, WriteFile, ReadFileEx, WriteFileEx, ReadScatter, WriteGather, DeviceControl,
    DirectoryChanges, LockFile, NtRead, NtWrite, NtReadScatter, NtWriteGather, NtControl, NtDirectory,
    WsaRecv, WsaSend, WsaRecvFrom, WsaSendTo, WsaControl, Accept, Connect, Disconnect, Transmit,
    OverlappedResult, WsaResult, Dequeue, DequeueBatch, NtDequeue, NtDequeueBatch, WaitSingle, WaitMultiple,
    RpcComplete, RpcInitialize
};
enum class AsyncIoSource : uint32_t { Result = 1, CompletionPort, Apc, Event, Return, Rpc };
enum class AsyncIoDomain : uint32_t { Win32 = 1, NtStatus, Winsock, Rpc };
constexpr bool IsValidAsyncIoSource(uint64_t value)
{
    return value >= static_cast<uint64_t>(AsyncIoSource::Result) &&
        value <= static_cast<uint64_t>(AsyncIoSource::Rpc);
}
constexpr bool IsValidAsyncIoDomain(uint64_t value)
{
    return value >= static_cast<uint64_t>(AsyncIoDomain::Win32) &&
        value <= static_cast<uint64_t>(AsyncIoDomain::Rpc);
}
enum class AsyncCallbackKind : uint32_t { None, Win32, Native, Winsock };

struct AsyncIoBuffer
{
    uint64_t address, bytes;
    uint32_t parameter, index;
};
struct AsyncIoBufferSnapshot
{
    uint64_t address, requested, completed;
    uint32_t parameter, index;
};
struct PendingIo
{
    uint64_t callId, group, control, file, event;
    uint32_t api, thread, next, bufferCount, controlParameter, flags;
    AsyncIoRole role;
    bool submitting;
    AsyncIoBuffer buffers[MaximumArguments];
};

enum class RpcDecoder : uint8_t
{
    None, Client2, Client3, Async2, Async3, Dcom2, Dcom3, Pickle, Pickle2, Pickle3, Client4, Async4, Pickle4, Client
};
enum class RpcValueType : uint16_t
{
    Unknown, UInt8, Int8, UInt16, Int16, UInt32, Int32, UInt64, Int64, Float32, Float64,
    Ansi, Utf16, Pointer, Structure, Array, Binding, AsyncHandle, Context, Custom, Union
};
enum RpcCaptureFlags : uint32_t
{
    RpcDescriptorValid = 1, RpcNdr64 = 2, RpcAsynchronous = 4, RpcPartial = 8, RpcOutputsDeferred = 16,
    RpcDescriptorUnreadable = 32, RpcPickling = 64, RpcObjectProcedure = 128, RpcEncoding = 256, RpcDecoding = 512
};
constexpr uint16_t RpcIn = 8, RpcOut = 16, RpcReturn = 32, RpcBaseType = 64, RpcByValue = 128, RpcSimpleRef = 256;
constexpr uint16_t RpcNoParent = UINT16_MAX;

struct RpcParameterInfo
{
    uint16_t argument, attributes;
    RpcValueType type;
    uint8_t pointerDepth, width;
    uint32_t memorySize;
};
struct RpcCallInfo
{
    GUID interfaceId;
    uint32_t procedure, flags;
    uint16_t major, minor, parameterCount;
    uint8_t prefix, argumentCount;
    RpcParameterInfo parameters[MaximumArguments + 1];
};
struct RpcValueInfo
{
    uint16_t node, parent;
    RpcValueType type;
    uint16_t flags;
    uint32_t offset, stride;
    uint64_t address;
};
static_assert(sizeof(RpcParameterInfo) == 12 && sizeof(RpcCallInfo) == 428 && sizeof(RpcValueInfo) == 24);

struct RpcCaptureState
{
    struct Parameter
    {
        uint64_t type, capacity;
        uint32_t stackOffset;
        uint16_t attributes;
        uint8_t baseType;
        bool capacityValid;
    };
    struct Array
    {
        uint64_t path, format, capacity;
        uint32_t parameter;
    };
    RpcCallInfo info{};
    Parameter parameters[MaximumArguments + 1]{};
    uint32_t stackBytes = 0, correlationBytes = 4, bindingOffset = UINT32_MAX;
    uint64_t argumentStack = 0, expressionOffsets = 0, expressionFormat = 0, marshalRoutines = 0;
    Array arrays[RpcMaxArrays]{};
    uint32_t arrayCount = 0;
    RpcDecoder decoder = RpcDecoder::None;
};

struct PendingRpc
{
    uint64_t control;
    Event event;
    RpcCaptureState state;
};

struct TransportHandles
{
    uint64_t mapping, data, space, ready, resume, breakpoint, controller, catalog, startupThread;
};
struct TransportStartup
{
    TransportHandles handles;
    uint64_t captureIdentity;
    volatile LONG owned;
    uint32_t reserved;
};
static_assert(sizeof(TransportHandles) == 72 && sizeof(TransportStartup) == 88);

template<class Character>
bool ParseTransportNumber(std::basic_string_view<Character> text, uint64_t& value)
{
    value = 0;
    for (auto character : text)
    {
        if (character < '0' || character > '9') return false;
        auto digit = static_cast<uint64_t>(character - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    }
    return !text.empty();
}

struct alignas(64) SharedHeader
{
    uint32_t magic;
    uint32_t version;
    uint32_t processId;
    uint32_t controllerId;
    uint32_t capacity;
    uint32_t stride;
    uint32_t payloadCapacity;
    uint32_t inlinePayloadCapacity;
    uint32_t overflowCapacity;
    uint32_t overflowStride;
    uint32_t overflowOffset;
    uint32_t bufferLimit;
    uint32_t mappingBytes;
    uint32_t stackDepth;
    uint32_t pageBytes;
    uint32_t followChildren;
    uint32_t rawPointerProbes;
    uint32_t installedExportCount;
    wchar_t catalogMapping[CatalogMappingCapacity];
    int64_t frequency;
    uint64_t captureIdentity;
    TransportHandles targetHandles;
    volatile LONGLONG moduleEpoch;
    volatile LONGLONG moduleHistoryLost;
    volatile LONGLONG moduleChangeWrite, moduleChangeRead;
    volatile LONG state;
    volatile LONG stop;
    volatile LONG capturePaused;
    uint32_t bootstrapDeferred;
    // Bootstrap stages: unarmed, APC queued, loader ready, collector permission granted.
    volatile LONG bootstrapState;
    volatile LONG error;
    volatile LONG debuggerActive;
    volatile LONG agentThreadId;
    volatile LONG waiters;
    volatile LONG instructionThreadId;
    volatile LONG entryApi;
    volatile LONG exitApi;
    uint32_t installedNativeCount;
    uint32_t availableNativeCount;
    uint32_t nativeExportCount;
    uint32_t installedWin32Count;
    uint32_t availableWin32Count;
    uint32_t installedComCount;
    volatile LONG managedState;
    uint32_t managedApiCount;
    uint32_t moduleRefreshError;
    volatile LONG instructionState;
    char unknownNativeExports[UnknownNativeExportsCapacity];
    volatile LONG excludedApiCount;
    alignas(8) volatile LONGLONG excludedApis[ApiExclusionSlots];
    alignas(8) volatile LONGLONG enabledFilters;
    volatile LONGLONG installedApis;
    volatile LONGLONG entryBreaks;
    volatile LONGLONG exitBreaks;
    volatile LONGLONG wrapGeneration;
    volatile LONGLONG nextCallId;
    // Admitted calls retain the agent's session mapping; recording calls still owe a published return.
    volatile LONGLONG activeCalls;
    volatile LONGLONG recordingCalls;
    volatile LONGLONG waitTicks;
    alignas(64) volatile LONGLONG freeSlots;
    volatile LONGLONG enqueue;
    alignas(64) volatile LONGLONG freeOverflowSlots;
    alignas(64) volatile LONGLONG readySlots;
    volatile LONGLONG published;
    alignas(64) volatile LONGLONG dequeue;
    Breakpoint breakpoint;
    ChildRequest children[ChildRequestCapacity];
    ThreadIdRequest threadIds;
    ModuleChange moduleChanges[ModuleHistoryCapacity];
    alignas(64) volatile LONG asyncLock, asyncPending, asyncReleased;
    uint32_t asyncFree, asyncBuckets[AsyncIoBuckets];
    volatile LONGLONG asyncUntracked, asyncCallbackErrors;
    PendingIo asyncIo[AsyncIoCapacity];
    alignas(64) volatile LONG rpcLock, rpcPending;
    PendingRpc rpcAsync[RpcAsyncCapacity];
};

// Atomic hash slots let capture threads check exclusions without locks, strings or allocations.
inline bool ApiExcluded(const SharedHeader& header, uint64_t hash)
{
    if (!header.excludedApiCount) return false;
    auto slot = static_cast<uint32_t>(hash) & (ApiExclusionSlots - 1);
    for (uint32_t probe = 0; probe < ApiExclusionSlots; ++probe)
    {
        const auto value = static_cast<uint64_t>(header.excludedApis[slot]);
        if (value == hash) return true;
        if (!value) return false;
        slot = (slot + 1) & (ApiExclusionSlots - 1);
    }
    return false;
}

struct alignas(8) OverflowSlot
{
    volatile LONGLONG next;
};
static_assert(sizeof(OverflowSlot) == 8);

struct alignas(64) Slot
{
    volatile LONGLONG next;
    Event event;
    uint32_t index;
    uint32_t overflowIndex;
    int32_t bufferDelta;
    uint32_t inputBytes;
    uint32_t payloadOffset;
    int64_t entryTimestamp;
};
static_assert(sizeof(Slot) == 384);
#pragma warning(pop)

inline uint32_t SlotMaxRemaining(const Slot* slot, const SharedHeader* header)
{
    const auto used = slot->payloadOffset + slot->event.payloadBytes;
    return used < header->payloadCapacity ? header->payloadCapacity - used : 0;
}

inline uint32_t Align64(uint32_t value) { return (value + 63) & ~uint32_t{63}; }
#ifdef DETOURIST_INSTRUCTION_CLIENT
int64_t Clock();
#else
inline int64_t Clock()
{
    LARGE_INTEGER value;
    QueryPerformanceCounter(&value);
    return value.QuadPart;
}
#endif
inline const ApiDefinition& Definition(Api api)
{
    static constexpr ApiDefinition unknown{Api::Count, "", "Unknown API", L"", 0};
    auto index = static_cast<uint32_t>(api);
    return index < std::size(ApiDefinitions) ? ApiDefinitions[index] : unknown;
}
#pragma warning(pop)
}
