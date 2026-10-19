#pragma once
#include "InstructionChannel.h"
#include "CaptureValues.h"
#include "AsyncIo.h"
#include "RpcCapture.h"
#include "CatalogView.h"
#include "ObserverBridge.h"
#include "CaptureTiming.h"
#include "ExportFunction.h"
#include <cstring>
#pragma warning(push, 0)
#include "dr_api.h"
#pragma warning(pop)

namespace Detourist
{
constexpr uint64_t MinimumUserAddress = 0x10000;
constexpr uint64_t MaximumUserAddress = 0x0000800000000000ULL;
constexpr uint32_t MaxComVtableSlots = 512;
constexpr uint32_t UnknownSlotCount = 3;
constexpr uint32_t FrameBlockCapacity = 32;
constexpr uint32_t SyscallFrameCapacity = 64;
constexpr size_t MaxFormatStringBytes = 4096;
constexpr size_t MaxX86InstructionBytes = 15;
constexpr int64_t NtRelativeMilliseconds(int64_t ms) { return -ms * 10000; }

inline bool InstructionStaticAddress(opnd_t operand)
{
#ifdef _WIN64
    return opnd_is_rel_addr(operand) || opnd_is_abs_addr(operand);
#else
    return opnd_is_abs_addr(operand);
#endif
}

struct RuntimeExport
{
    const char* name;
    const char* module;
    const wchar_t* description;
    uint32_t argumentCount;
    ExportSignature signature;
    ExportParameter parameters[MaximumArguments];
    ExportResultRule resultRule;
    uint8_t resultSuccessCount;
    const uint32_t* resultSuccesses;
    uint32_t interfaceParameters;
    uint32_t countedResultBytes;
    uint16_t resultInterfaceIndex;
    const ExportMember* members;
    uint32_t memberCount;
    uint32_t rawTailStart;
    ExportValueKind resultCaptureKind;
    const RuntimeExport* categorySource;

    bool IsAviSave() const
    {
        return rawTailStart == 6 && !_stricmp(module, "avifil32.dll") &&
            (!strcmp(name, "AVISave") || !strcmp(name, "AVISaveA") || !strcmp(name, "AVISaveW"));
    }
    bool IsAuthzAudit() const
    {
        return rawTailStart == 5 && !_stricmp(module, "authz.dll") && !strcmp(name, "AuthzReportSecurityEvent");
    }
    bool IsShellMessage() const
    {
        return rawTailStart == 5 && (!_stricmp(module, "shlwapi.dll") || !_stricmp(module, "shell32.dll")) &&
            (!strcmp(name, "ShellMessageBoxA") || !strcmp(name, "ShellMessageBoxW"));
    }
    bool IsPromptUser() const
    {
        return rawTailStart == 2 && !_stricmp(module, "oledlg.dll") &&
            (!strcmp(name, "OleUIPromptUserA") || !strcmp(name, "OleUIPromptUserW"));
    }
    bool IsWdsClientLog() const
    {
        return rawTailStart == 3 && !_stricmp(module, "wdsclientapi.dll") && !strcmp(name, "WdsCliLog");
    }
    uint32_t CapturedArgumentCount() const
    {
        return rawTailStart || RpcDecoderFor(module, name) != RpcDecoder::None ? MaximumArguments : argumentCount;
    }
};

struct RuntimeInterface
{
    GUID iid;
    const char* name;
    uint32_t firstSlot, slotCount;
    bool comPrefix;
};

struct InstructionDefinition
{
    DynamicApiMetadata metadata;
    Api typed, id;
    uint64_t mask;
    uint64_t categoryMask;
    uint64_t nameHash, sourceNameHash;
    ExportSignature signature;
    AsyncIoRole asyncRole;
    uint32_t interfaceInputs;
    const RuntimeExport* runtime;
    void* address;
    void* module;
    InstructionDefinition* next;
    InstructionDefinition* nextAll;
    InstructionDefinition* volatile variants;
    InstructionDefinition* nextVariant;
    void* interfaceTable;
    void** marshalSlot;
    void* marshalOriginal;
    void* marshalTarget;
    uint32_t marshalOperation;
    volatile LONG marshalBytes;
    uint32_t interfaceSlot;
    uint64_t interfaceGeneration;
    void* volatile rttiLocator;
    volatile LONG published, queryProbe, sharedComAddress, sharedExport, wrapped;
    bool known, interfaceWrapPending, retired, continuation, coverageCounted, entryOnly, provisional, ambiguousExport,
        stackProbe, optionalMode, callbackRegistration, wglLookup, nativeImportAlias, rpcProxy;
};

struct InstructionFrame
{
    InstructionChannel* transport;
    Event event;
    CaptureClock* clock;
    int64_t invocationStarted;
    InstructionDefinition* definition;
    InstructionDefinition* nativeBoundary;
    uint64_t nativeCallId, nativeParentId;
    uint32_t nativeDepth, nativeFlags;
    bool nativeRecord;
    uint64_t mask;
    uint64_t stackPointer;
    uint64_t stack[MaximumStack];
    uint32_t stackCount, stackFlags;
    uint64_t returnBuffer;
    uint64_t captureLimits[MaximumArguments];
    MruCaptureState mru;
    AsyncIoRole asyncRole;
    RpcCaptureState rpc;
    uint32_t requestedBytes, initializedOutputs;
    ChildRequest* child;
    uint32_t childFlags, childOutput, childFlagIndex;
    ObserverContext previousObserver;
    GUID queryIdentity;
    int64_t queryTimestamp;
    uint32_t queryError;
    bool queryProbe, queryRecord, formatOutputs;
    bool active, counted, record, nativeChild, suppressed, observerSet, suspended, mruOnly;
    InstructionFrame* previous;
    InstructionFrame* nextFree;
};

struct InstructionFrames
{
    InstructionFrames* next;
    InstructionFrame frames[FrameBlockCapacity];
};

struct InstructionSyscalls
{
    InstructionSyscalls* parent;
    uint32_t depth, overflow, suspended;
    InstructionFrame frames[SyscallFrameCapacity];
};

struct InstructionThread
{
    CaptureClock clock;
    InstructionFrames* blocks;
    InstructionFrame* freeFrames;
    InstructionFrame* current;
    uint32_t allocatedFrames;
    void* comTarget;
    uint64_t comInstance, comCaller;
    uint32_t comSlot;
};

ExportSignature PublicSignature(Api api);
ExportSignature SignatureFor(Api api);
const RuntimeExport* RuntimeDefinitionFor(const char* module, const char* name);
const RuntimeExport* RegisteredCallbackFor(const char* module, const char* name);
void DiscoverRegisteredCallbacks(InstructionFrame& call);
void FreeRegisteredCallbacks();
void InitializeCaptureCatalog();
void FreeCaptureCatalog();
const RuntimeInterface* RuntimeInterfaceFor(const GUID& iid);
const RuntimeExport* RuntimeInterfaceMethod(const RuntimeInterface& contract, uint32_t slot);
const GUID* RuntimeInterfaceIdentity(uint16_t index);
bool RuntimeImplicitArrayCount(const InstructionFrame& call, uint32_t index, uint64_t& count);
struct FormatCaptureResult
{
    uint32_t recognized = 0;
    uint8_t formatParameter = 0, listParameter = 0, argumentCount = 0;
    bool complete = false;
};
static_assert(sizeof(FormatCaptureResult) == 8);
void CaptureRuntimeParameters(InstructionFrame& call, Slot* slot, bool leaving, bool omitLast = false);
void CaptureRuntimeAviSave(InstructionFrame& call, Slot* slot, bool leaving);
void ReadRuntimeAuthzArguments(InstructionFrame& call);
void CaptureRuntimeAuthzAudit(InstructionFrame& call, Slot* slot, bool leaving);
bool IsFormatCrt(const char* module);
FormatCaptureResult CaptureRuntimeFormat(InstructionFrame& call, Slot* slot, bool leaving);
FormatCaptureResult CaptureRuntimeScan(InstructionFrame& call, Slot* slot, bool leaving);
FormatCaptureResult CaptureRuntimeMessage(InstructionFrame& call, Slot* slot, bool leaving);
FormatCaptureResult CaptureRuntimePrompt(InstructionFrame& call, Slot* slot, bool leaving);
FormatCaptureResult CaptureRuntimeWdsLog(InstructionFrame& call, Slot* slot, bool leaving);
bool CurrentFormatLocale(InstructionFrame& call, bool ucrt, void*& information, bool completed);
bool FormatCharacterWidths(InstructionFrame& call, uint64_t localeAddress, bool ucrt,
    uint8_t (&widths)[256], bool& utf8, bool completed = false);
uint32_t CaptureRuntimeBer(InstructionFrame& call, Slot* slot, bool leaving);
uint32_t CaptureRuntimeTraceMessage(InstructionFrame& call, Slot* slot, bool leaving);
void CapturePublicParameters(InstructionFrame& call, Slot* slot, bool leaving);
void CaptureBuiltinParameters(InstructionFrame& call, Slot* slot, bool leaving);
uint32_t PublicInterfaceOutputs(Api api);
const GUID* PublicInterfaceOutput(Api api, uint32_t parameter);
uint32_t PublicInterfaceInputs(Api api);
const GUID* PublicInterfaceInput(Api api, uint32_t parameter);
ExportSignature ComSignature(Api api);
void CaptureInstructionCom(InstructionFrame& call, Slot* slot, bool leaving);
void DiscoverInstructionCom(InstructionFrame& call);
void DiscoverComCall(void* target, uintptr_t instance, uintptr_t base, uint32_t slot, uintptr_t caller);
void ForgetComTables(const module_data_t* module);
bool ValidateComGeneration(void* table, uint64_t generation);
void DiscoverQueryInterface(void* target, uintptr_t instance, uintptr_t identity, uintptr_t output);
bool ConfirmQueryInterface(InstructionFrame& call);
void DiscoverInstructionInputs(InstructionFrame& call);
void DiscoverImageInterfaces(const module_data_t* module, uint64_t sections, uint16_t count);
void DiscoverRuntimeInterfaces(InstructionFrame& call, bool leaving);
void ObserveInterfaceMethod(void* address, void* table, const GUID& iid, uint32_t slot, Api typed,
    const RuntimeInterface* contract, bool provisional = false, const char* typeName = nullptr,
    void* rttiLocator = nullptr, bool queryProbe = false, uint64_t generation = 0);
bool ResolveImageInterface(void* table, uint64_t instance, void* locator);
InstructionDefinition* ResolveInterfaceDefinition(InstructionDefinition* definition, uint64_t instance,
    uint32_t slot = UINT32_MAX);
bool ExportFailure(const InstructionDefinition& definition, uint64_t result);
bool InstructionFailure(Api api, uint64_t result);
void PublishInstruction(InstructionFrame& call, bool leaving);
void PublishDefinition(InstructionDefinition& definition);
void CopyDescription(wchar_t* output, size_t capacity, const wchar_t* text);
Api FindExportType(const char* module, const char* name);
uint32_t RawWin32uArguments(const char* name);
InstructionDefinition* ExportDefinitionAt(void* address);
void InitializeExports();
void DiscoverExports(const module_data_t* module);
void RemoveExports(const module_data_t* module);
void FreeExports();
void EndExportThread(void* context, InstructionThread& thread);
bool PrepareInstructionChild(InstructionFrame& call);
void CompleteInstructionChild(InstructionFrame& call, bool success);
bool InstructionBreakpoint(InstructionFrame& call, bool leaving);
void SetApplicationError(void* context, uint32_t error);
uint32_t ApplicationError(void* context);
bool InstructionObserver(void* context, uint64_t caller, ObserverContext* observer = nullptr);
void SetInstructionObserver(void* context, const ObserverContext& observer);
bool ReadInstructionString(const char* source, char* output, size_t capacity);
InstructionDefinition* ResolveInstructionImport(InstructionDefinition* definition, uint64_t caller);
void ForgetInstructionImports(const module_data_t* module);
void FreeInstructionImports();
void ExportEntered(void* wrapped, void** state);
void ExportLeft(void* wrapped, void* state);
bool NativeOwnsCall(const InstructionDefinition& definition, const ObserverContext& observer);
void ObserveRpcSerializationCall(Api api, const uint64_t* arguments, uint64_t result, bool leaving);
void DiscoverReturnedExtensions(InstructionFrame& frame);
void ObserverModule(const module_data_t* module);
void CaptureInstructionStack(void* context, InstructionFrame& frame, const dr_mcontext_t& machine, bool atCaller);
uint64_t ReadInstructionArgument(const dr_mcontext_t& machine, const ExportSignature& signature, uint32_t index);
bool WriteInstructionArgument(void* wrapped, dr_mcontext_t& machine, const ExportSignature& signature,
    uint32_t index, uint64_t value);
uint64_t PrepareAsyncCallback(void* context, InstructionFrame& frame, uint32_t& parameter);
extern InstructionChannel InstructionTransport;
extern void* DefinitionLock;
extern int ThreadSlot;
extern int SyscallSlot;
}
