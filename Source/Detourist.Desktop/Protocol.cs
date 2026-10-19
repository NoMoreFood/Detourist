namespace Detourist.Desktop;

internal static class Protocol
{
    public const int MaximumStack = 48;
    public const int MaximumArguments = 32;
    public const int MinimumBufferLimit = 16;
    public const int DefaultBufferLimit = 1024;
    public const int MaximumBufferLimit = 65536;
    public const int ApiCatalogSchemaVersion = 15;
    public const int MaxFormatStringChars = 4096;
    public const int MaxFormatSampleBytes = 8192;
    public const int MaxExpandedElements = 128;
    public const int MaxExpansionDepth = 12;
    public const int MaxPreviewChars = 100;
    public const int UiDebounceMs = 250;
    public const double WorkAreaMargin = 30;

    public const long ManagedApiStart = 0x40000000;
    public const long InterfaceApiStart = 0x50000000;
    public const long SyscallApiStart = 0x60000000;
    public const long ExportApiStart = 0x70000000;

    public static bool IsManagedApi(long api) => api is >= ManagedApiStart and < InterfaceApiStart;
}

[Flags]
internal enum ApiSourceMask : ulong
{
    Native = 1UL << 18,
    Win32 = 1UL << 19,
    Com = 1UL << 20,
    Managed = 1UL << 21,
    Win32u = 1UL << 22,
    DirectSyscalls = 1UL << 23
}

internal enum InstructionState : long
{
    Inactive = 0,
    Active = 1,
    Failed = 2,
    Stopped = 3,
    Starting = 4,
    Stopping = 5
}

internal enum ManagedRuntimeState : long
{
    Inactive = 0,
    Active = 1,
    Failed = 2,
    Attaching = 3
}

[Flags]
internal enum EventFlags : long
{
    None = 0,
    Failed = 1,
    Skipped = 2,
    Unwound = 4,
    AsyncPending = 8,
    Edited = 16,
    Continuation = 32,
    StackUnavailable = 64,
    Syscall = 128,
    RawArguments = 256,
    KernelDispatcher = 512,
    OptionalArgumentAbsent = 1024,
    FormattedArguments = 2048,
    AsyncCompleted = 1L << 18,
    AsyncCancelled = 1L << 19,
    DurationMeasured = 1L << 20
}

[Flags]
internal enum ValueFlags : long
{
    None = 0,
    Truncated = 1,
    Unreadable = 2,
    Pending = 4,
    ReferencedData = 8,
    MemberData = 16,
    AutomationElement = 32,
    StringArrayElement = 64,
    LdapData = 128,
    SyncAllData = 256,
    ReplicaData = 512,
    NetApiData = 1024,
    EtwData = 2048,
    SidData = 4096,
    NetApiBytesData = 8192,
    SecurityDescriptorData = 16384,
    AuditData = 32768
}

internal enum ValueKind : long
{
    Bytes = 0,
    Utf16 = 1,
    Scalar = 2,
    FindData = 3,
    ProcessInformation = 4,
    Stack = 5,
    ObjectAttributes = 6,
    IoStatus = 7,
    SafeArray = 8,
    SafeArrayData = 9,
    PropertyVector = 10,
    PropertyVectorData = 11,
    ManagedArray = 12,
    AutomationLink = 13,
    PropertyClipboard = 14,
    RpcCall = 15,
    RpcValue = 16
}

internal enum AsyncIoSource : long
{
    Result = 1,
    CompletionPort = 2,
    Apc = 3,
    Event = 4,
    Return = 5,
    Rpc = 6
}

internal enum AsyncIoDomain : long
{
    Win32 = 1,
    NtStatus = 2,
    Winsock = 3,
    Rpc = 4
}

[Flags]
internal enum RpcCaptureFlags : long
{
    DescriptorValid = 1,
    Ndr64 = 2,
    Asynchronous = 4,
    Partial = 8,
    OutputsDeferred = 16,
    DescriptorUnreadable = 32,
    Pickling = 64,
    ObjectProcedure = 128,
    Encoding = 256,
    Decoding = 512
}

[Flags]
internal enum RpcParameterFlags : long
{
    In = 8,
    Out = 16,
    Return = 32,
    BaseType = 64,
    ByValue = 128,
    SimpleRef = 256
}

internal enum RpcValueType : long
{
    Unknown = 0,
    UInt8 = 1,
    Int8 = 2,
    UInt16 = 3,
    Int16 = 4,
    UInt32 = 5,
    Int32 = 6,
    UInt64 = 7,
    Int64 = 8,
    Float32 = 9,
    Float64 = 10,
    Ansi = 11,
    Utf16 = 12,
    Pointer = 13,
    Structure = 14,
    Array = 15,
    Binding = 16,
    AsyncHandle = 17,
    Context = 18,
    Custom = 19,
    Union = 20
}
