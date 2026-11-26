#pragma once
#include "Protocol.h"

namespace Detourist
{
constexpr uint32_t CatalogMagic = 0x43415444;
constexpr uint32_t CatalogVersion = 16;
constexpr int ApiCatalogSchemaVersion = 15;
constexpr uint32_t CatalogBudget = 64 * 1024 * 1024;
constexpr uint32_t MaximumExportArgumentBytes = 64;
constexpr uint32_t MaxModuleAliasCount = 1024;
constexpr uint32_t MaxResultSuccessCount = 8;
constexpr size_t CatalogTableAlignment = 4;

enum class ExportCallingConvention : uint8_t { Unknown, Cdecl, Stdcall, Fastcall };

struct ExportSignature
{
    uint8_t argumentBytes[MaximumArguments];
    uint8_t floatingArguments, resultBytes;
    bool floatingResult, supported;
    uint8_t interfaceIdIndex, interfaceOutputIndex;
    ExportCallingConvention callingConvention;
    uint32_t returnBufferBytes;
};

enum class ExportValueKind : uint8_t
{
    Bytes, Scalar, Utf16, Ansi, UnicodeString, AnsiString, IndirectBytes, Bstr, HString, CountedBytes, PropertyVariant,
    BstrArray, MapiAddressList, MapiPropertyArray, LdapModAnsi, LdapModUtf16, AnsiStringPairs, Utf16StringPairs,
    SyncAllErrorsAnsi, SyncAllErrorsUtf16, ReplicaInformation, BerValue,
    LdapControlAnsi, LdapControlUtf16, LdapControlsAnsi, LdapControlsUtf16, NetApiRecords,
    EtwDataDescriptors, ClassicEtwEvent, BerValues, RequiredSize, SafeArray, ReturnedSpan, X509Certificate,
    SoundAnsi, SoundUtf16, ObjectAttributes, IoStatus, AuditParams, Sid,
    SecurityDescriptor, SecurityDescriptors, AuthzRequest, AuthzReply, SamRidEnumeration, SamSidEnumeration,
    AuthzOperations, Utf16StringArray, Utf16MultiString, RequiredSizeLastError, PrintDocumentEvent, FailureEapError,
    RtmBuffer, PrinterPayload
};

constexpr uint8_t ExportInput = 1;
constexpr uint8_t ExportOutput = 2;
constexpr uint8_t ExportNegativeTerminated = 4;
constexpr uint8_t ExportInlineRecord = 4;
constexpr uint8_t ExportTerminated = 8;
constexpr uint8_t ExportIndirectRecord = 64;
constexpr uint8_t ExportIndirectSelector = 128;
constexpr uint8_t ExportAdvancingBuffer = 16;
constexpr uint8_t ExportByReference = 16;
constexpr uint8_t ExportReturnedBuffer = 32;
constexpr uint8_t ExportInterfaceArray = 64;
constexpr uint8_t ExportAutomationVariant = 128;
constexpr uint8_t ExportActualReturn = UINT8_MAX;

struct ExportParameter
{
    uint32_t bytes;
    int8_t extentIndex;
    uint8_t indirectBytes;
    uint16_t multiplier;
    uint8_t flags;
    ExportValueKind kind;
    uint8_t actualIndex, actualIndirectBytes;
    uint16_t interfaceIndex;
    uint16_t prefixBytes;
    uint8_t productIndex;
    uint16_t actualPrefixBytes;
    uint16_t actualOffset;
};

struct ExportMember
{
    uint16_t parameter, pointerOffset, extentOffset, multiplier;
    uint8_t extentBytes, flags;
    uint16_t productOffset;
    uint8_t productBytes, conditionIndex;
    uint16_t reserved;
    uint32_t conditionMask;
};

struct CatalogHeader
{
    uint32_t magic, version, bytes, builtinCount, builtinOffset, exportCount;
    uint32_t planCount, planOffset, interfaceCount, interfaceOffset, slotCount, slotOffset;
    uint32_t ordinalCount, ordinalOffset, moduleAliasCount, moduleAliasOffset;
    uint32_t categoryCount, categoryOffset, categoryRuleCount, categoryRuleOffset;
    uint32_t pointerSize, reserved;
};

struct CatalogModuleAlias
{
    uint32_t alias, module;
};

struct CatalogCategory
{
    uint32_t id, name, description;
};

enum class CategoryTarget : uint32_t { Name, Module };
enum class CategoryMatch : uint32_t { Prefix, Contains, Exact };

struct CatalogCategoryRule
{
    ApiCategory category;
    CategoryTarget target;
    CategoryMatch match;
    uint32_t pattern, patternBytes, replacement, replacementBytes;
};

struct CatalogApi
{
    uint32_t id, module, name, description, argumentCount;
    uint32_t planIndex = UINT32_MAX;
    uint32_t hookFlags = 0, nativeName = 0;
};

enum class ExportResultRule : uint8_t
{
    Unknown, Negative, Zero, MinusOne, NonZero, NonPositive
};

constexpr bool ExportResultFailed(ExportResultRule rule, uint8_t bytes, uint64_t result)
{
    if (rule == ExportResultRule::Unknown) return false;
    auto mask = bytes == 1 ? UINT64_C(0xFF) : bytes == 2 ? UINT64_C(0xFFFF) :
        bytes == 4 ? UINT64_C(0xFFFFFFFF) : UINT64_MAX;
    if (rule == ExportResultRule::Negative || rule == ExportResultRule::NonPositive)
    {
        auto sign = bytes == 1 ? UINT64_C(0x80) : bytes == 2 ? UINT64_C(0x8000) :
            bytes == 4 ? UINT64_C(0x80000000) : UINT64_C(0x8000000000000000);
        if ((result & sign) != 0) return true;
        return rule == ExportResultRule::NonPositive && !(result & mask);
    }
    if (rule == ExportResultRule::NonZero) return (result & mask) != 0;
    return rule == ExportResultRule::Zero ? !(result & mask) : (result & mask) == mask;
}

// Explicit statuses define an unknown convention or supplement a known convention at its scalar width.
constexpr bool ExportResultFailed(ExportResultRule rule, uint8_t bytes, uint64_t result,
    const uint32_t* successes, uint8_t count)
{
    if (rule == ExportResultRule::Unknown ? !count : !ExportResultFailed(rule, bytes, result)) return false;
    auto mask = bytes == 1 ? UINT64_C(0xff) : bytes == 2 ? UINT64_C(0xffff) :
        bytes == 4 ? UINT64_C(0xffffffff) : UINT64_MAX;
    for (uint8_t index = 0; index < count; ++index)
        if ((result & mask) == successes[index]) return false;
    return true;
}

struct CatalogPlan
{
    uint32_t name, module, description, parameters, argumentCount;
    ExportSignature signature;
    uint32_t interfaceParameters, countedResultBytes;
    ExportResultRule resultRule;
    uint8_t resultSuccessCount;
    uint32_t members, memberCount;
    uint16_t resultInterfaceIndex, rawTailStart;
    ExportValueKind resultCaptureKind;
    uint32_t resultSuccesses;
};

struct CatalogInterface
{
    GUID iid;
    uint32_t name, firstSlot, slotCount, rttiName;
};

struct CatalogOrdinal
{
    uint32_t module, ordinal, name;
};

class CatalogView
{
public:
    bool Open(const void* data, size_t bytes, uint32_t pointerSize = sizeof(void*));
    const CatalogHeader* Header() const { return header_; }
    const CatalogApi* Builtins() const;
    const CatalogPlan* BuiltinPlan(Api api) const;
    const CatalogPlan* Plans() const;
    const CatalogInterface* Interfaces() const;
    const CatalogOrdinal* Ordinals() const;
    const CatalogModuleAlias* ModuleAliases() const;
    const char* CanonicalModule(const char* module) const;
    const CatalogCategory* Categories() const;
    const CatalogCategoryRule* CategoryRules() const;
    ApiCategory ClassifyApi(const char* module, const char* name) const;
    const char* OrdinalName(const char* module, uint32_t ordinal) const;
    uint32_t NameOrdinal(const char* module, const char* name) const;
    const uint32_t* Slots() const;
    const char* Text(uint32_t offset) const;
    const wchar_t* WideText(uint32_t offset) const;
    const ExportParameter* Parameters(const CatalogPlan& plan) const;
    const ExportMember* Members(const CatalogPlan& plan) const;
    const uint32_t* SuccessValues(const CatalogPlan& plan) const;
private:
    const std::byte* data_ = nullptr;
    const CatalogHeader* header_ = nullptr;
};

bool PublicFailure(Api api, uint64_t result);
bool CatalogModuleMatches(const char* pattern, const char* module);
bool BindApiMetadata(const CatalogView& catalog);
bool BindApiDefinitions(const CatalogView& catalog);
static_assert(sizeof(ExportSignature) == 44 && sizeof(ExportParameter) == 24 && sizeof(ExportMember) == 20 &&
    sizeof(CatalogPlan) == 96 && sizeof(CatalogInterface) == 32 && sizeof(CatalogOrdinal) == 12 &&
    sizeof(CatalogModuleAlias) == 8 && sizeof(CatalogCategory) == 12 && sizeof(CatalogCategoryRule) == 28);
}
