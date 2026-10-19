#include "ManagedMetadata.h"
#include <wrl/client.h>
#include <algorithm>
#include <array>
#include <stdexcept>
#include <cwctype>
#include <set>
#include <bcrypt.h>
#include <nlohmann/json.hpp>
#include "WinSupport.h"

namespace Detourist
{
using Microsoft::WRL::ComPtr;
constexpr size_t Sha1HashBytes = 20;
constexpr size_t PublicKeyTokenBytes = 8;
constexpr size_t MetadataShortNameCapacity = 256;
constexpr size_t MetadataLocaleCapacity = 128;
constexpr size_t MetadataParameterNameCapacity = 512;
constexpr size_t MetadataScopeNameCapacity = 1024;
constexpr size_t MetadataTypeNameCapacity = 2048;
constexpr size_t MaxObservedModules = 4096;
constexpr size_t MaxObservedClasses = 65536;
constexpr uint32_t MaxTypeResolutionDepth = 16;
constexpr size_t MaxClassVisitCount = 256;
constexpr size_t MaxGenericArguments = 256;
constexpr uint32_t MaxLayoutDepth = 24;
constexpr size_t MaxClassFields = 256;
constexpr uint32_t MaxSignatureDepth = 32;
constexpr uint32_t MaxArrayRank = 32;
constexpr uint32_t MaxMethodParameters = 1024;
constexpr uint32_t TypeDefOrRefTagMask = 3;
constexpr uint32_t TypeDefOrRefTagBits = 2;

bool IsValueTypeBase(IMetaDataImport* metadata, mdToken base)
{
    wchar_t name[MetadataShortNameCapacity]{};
    if (TypeFromToken(base) == mdtTypeRef)
        metadata->GetTypeRefProps(base, nullptr, name, _countof(name), nullptr);
    else if (TypeFromToken(base) == mdtTypeDef)
        metadata->GetTypeDefProps(base, name, _countof(name), nullptr, nullptr, nullptr);
    return !wcscmp(name, L"System.ValueType") || !wcscmp(name, L"System.Enum");
}

uint32_t ManagedScalarBytes(CorElementType element)
{
    switch (element)
    {
    case ELEMENT_TYPE_BOOLEAN: case ELEMENT_TYPE_I1: case ELEMENT_TYPE_U1: return 1;
    case ELEMENT_TYPE_CHAR: case ELEMENT_TYPE_I2: case ELEMENT_TYPE_U2: return 2;
    case ELEMENT_TYPE_I4: case ELEMENT_TYPE_U4: case ELEMENT_TYPE_R4: return 4;
    case ELEMENT_TYPE_I8: case ELEMENT_TYPE_U8: case ELEMENT_TYPE_R8: return 8;
    case ELEMENT_TYPE_I: case ELEMENT_TYPE_U: return sizeof(void*);
    default: return 0;
    }
}

constexpr std::pair<CorElementType, const wchar_t*> ManagedPrimitives[] = {
    {ELEMENT_TYPE_BOOLEAN, L"System.Boolean"}, {ELEMENT_TYPE_CHAR, L"System.Char"},
    {ELEMENT_TYPE_I1, L"System.SByte"}, {ELEMENT_TYPE_U1, L"System.Byte"},
    {ELEMENT_TYPE_I2, L"System.Int16"}, {ELEMENT_TYPE_U2, L"System.UInt16"},
    {ELEMENT_TYPE_I4, L"System.Int32"}, {ELEMENT_TYPE_U4, L"System.UInt32"},
    {ELEMENT_TYPE_I8, L"System.Int64"}, {ELEMENT_TYPE_U8, L"System.UInt64"},
    {ELEMENT_TYPE_R4, L"System.Single"}, {ELEMENT_TYPE_R8, L"System.Double"},
    {ELEMENT_TYPE_I, L"System.IntPtr"}, {ELEMENT_TYPE_U, L"System.UIntPtr"},
    {ELEMENT_TYPE_STRING, L"System.String"}, {ELEMENT_TYPE_OBJECT, L"System.Object"}};

bool ReadPublicKeyToken(const void* publicKey, ULONG keyBytes, DWORD flags, uint64_t& token)
{
    if (!publicKey) return false;
    if (flags & afPublicKey)
    {
        UCHAR hash[Sha1HashBytes]{};
        if (BCryptHash(BCRYPT_SHA1_ALG_HANDLE, nullptr, 0,
            const_cast<PUCHAR>(static_cast<const UCHAR*>(publicKey)), keyBytes, hash, sizeof(hash)) < 0) return false;
        for (uint32_t index = 0; index < PublicKeyTokenBytes; ++index)
            token = (token << 8) | hash[Sha1HashBytes - 1 - index];
    }
    else
    {
        if (keyBytes != PublicKeyTokenBytes) return false;
        auto bytes = static_cast<const UCHAR*>(publicKey);
        for (uint32_t index = 0; index < PublicKeyTokenBytes; ++index) token = (token << 8) | bytes[index];
    }
    return true;
}

std::wstring ManagedAssemblyIdentity(IMetaDataAssemblyImport* metadata, mdToken token)
{
    wchar_t name[MetadataScopeNameCapacity]{}, locale[MetadataLocaleCapacity]{};
    ASSEMBLYMETADATA identity{};
    identity.szLocale = locale;
    identity.cbLocale = _countof(locale);
    const void* key = nullptr;
    ULONG keyBytes = 0, length = 0;
    DWORD flags = 0;
    auto result = TypeFromToken(token) == mdtAssemblyRef ?
        metadata->GetAssemblyRefProps(token, &key, &keyBytes, name, _countof(name), &length,
            &identity, nullptr, nullptr, &flags) :
        metadata->GetAssemblyProps(token, &key, &keyBytes, nullptr, name, _countof(name), &length,
            &identity, &flags);
    if (FAILED(result) || !length || length > _countof(name) || identity.cbLocale > _countof(locale)) return {};

    // Compare full assembly identities, normalizing full public keys to their reference tokens.
    uint64_t keyToken = 0;
    if (keyBytes && !ReadPublicKeyToken(key, keyBytes, flags, keyToken)) return {};
    auto text = std::wstring(name) + L"|" + locale + L"|" + std::to_wstring(identity.usMajorVersion) + L"." +
        std::to_wstring(identity.usMinorVersion) + L"." + std::to_wstring(identity.usBuildNumber) + L"." +
        std::to_wstring(identity.usRevisionNumber) + L"|" + std::to_wstring(keyToken);
    std::transform(text.begin(), text.end(), text.begin(), towlower);
    return text;
}

void ManagedClasses::ObserveModule(ICorProfilerInfo2* profiler, ModuleID module)
{
    {
        std::lock_guard lock(mutex_);
        if (modules_.contains(module)) return;
    }
    Module entry;
    if (FAILED(profiler->GetModuleInfo(module, nullptr, 0, nullptr, nullptr, &entry.assembly)) ||
        FAILED(profiler->GetAssemblyInfo(entry.assembly, 0, nullptr, nullptr, nullptr, &entry.manifest)) ||
        !entry.manifest || FAILED(profiler->GetModuleMetaData(module, ofRead, IID_IMetaDataImport,
            reinterpret_cast<IUnknown**>(entry.metadata.GetAddressOf()))) || !entry.metadata) return;
    wchar_t name[MetadataScopeNameCapacity]{};
    ULONG length = 0;
    if (FAILED(entry.metadata->GetScopeProps(name, _countof(name), &length, nullptr)) ||
        !length || length > _countof(name)) return;
    entry.name = name;
    std::transform(entry.name.begin(), entry.name.end(), entry.name.begin(), towlower);
    ComPtr<IMetaDataAssemblyImport> assembly;
    mdAssembly token = 0;
    if (FAILED(profiler->GetModuleMetaData(entry.manifest, ofRead, IID_IMetaDataAssemblyImport,
        reinterpret_cast<IUnknown**>(assembly.GetAddressOf()))) ||
        !assembly || FAILED(assembly->GetAssemblyFromScope(&token))) return;
    entry.identity = ManagedAssemblyIdentity(assembly.Get(), token);
    if (entry.identity.empty()) return;
    entry.coreLibrary = (entry.name == L"mscorlib.dll" || entry.name == L"system.private.corelib.dll") &&
        FrameworkIdentity(entry.metadata.Get());
    if (entry.manifest != module) ObserveModule(profiler, entry.manifest);
    std::lock_guard lock(mutex_);
    if (modules_.size() < MaxObservedModules) modules_.try_emplace(module, std::move(entry));
}

void ManagedClasses::ForgetModule(ModuleID module)
{
    std::lock_guard lock(mutex_);
    modules_.erase(module);
    std::erase_if(classes_, [module](const auto& entry) { return std::get<0>(entry.first) == module; });
}

ModuleID ManagedClasses::Assembly(ModuleID source, mdAssemblyRef reference)
{
    auto owner = modules_.find(source);
    ComPtr<IMetaDataAssemblyImport> metadata;
    if (owner == modules_.end() || FAILED(owner->second.metadata->QueryInterface(IID_IMetaDataAssemblyImport,
        reinterpret_cast<void**>(metadata.GetAddressOf())))) return 0;
    auto identity = ManagedAssemblyIdentity(metadata.Get(), reference);
    if (identity.empty()) return 0;
    ModuleID matched = 0;
    for (const auto& [module, entry] : modules_)
        if (module == entry.manifest && entry.identity == identity)
        {
            if (matched) return 0;
            matched = module;
        }
    return matched;
}

ManagedClasses::Definition ManagedClasses::Named(ModuleID module, const wchar_t* name,
    mdTypeDef enclosing, uint32_t depth)
{
    auto found = modules_.find(module);
    if (depth > MaxTypeResolutionDepth || found == modules_.end()) return {};
    mdTypeDef token = 0;
    if (SUCCEEDED(found->second.metadata->FindTypeDefByName(name, enclosing, &token))) return {module, token};
    if (enclosing) return {};

    // Forwarders and multi-module assemblies resolve only through metadata from loaded modules.
    ComPtr<IMetaDataAssemblyImport> metadata;
    mdExportedType exported = 0;
    mdToken implementation = 0;
    if (FAILED(found->second.metadata->QueryInterface(IID_IMetaDataAssemblyImport,
        reinterpret_cast<void**>(metadata.GetAddressOf())))) return {};
    if (FAILED(metadata->FindExportedTypeByName(name, 0, &exported)))
    {
        // Dynamic assemblies can expose loaded types before emitting an exported-type manifest entry.
        if (module != found->second.manifest) return {};
        Definition matched{};
        for (const auto& [candidate, entry] : modules_)
            if (candidate != module && entry.assembly == found->second.assembly &&
                SUCCEEDED(entry.metadata->FindTypeDefByName(name, 0, &token)))
            {
                if (matched.first) return {};
                matched = {candidate, token};
            }
        return matched;
    }
    if (FAILED(metadata->GetExportedTypeProps(exported, nullptr, 0, nullptr, &implementation, nullptr, nullptr)))
        return {};
    if (TypeFromToken(implementation) == mdtAssemblyRef)
        return Named(Assembly(module, implementation), name, 0, depth + 1);
    if (TypeFromToken(implementation) != mdtFile) return {};
    wchar_t file[MetadataScopeNameCapacity]{};
    ULONG length = 0;
    if (FAILED(metadata->GetFileProps(implementation, file, _countof(file), &length, nullptr, nullptr, nullptr)) ||
        !length || length > _countof(file)) return {};
    ModuleID matched = 0;
    for (const auto& [candidate, entry] : modules_)
        if (entry.assembly == found->second.assembly && !_wcsicmp(entry.name.c_str(), file))
        {
            if (matched) return {};
            matched = candidate;
        }
    return Named(matched, name, 0, depth + 1);
}

ManagedClasses::Definition ManagedClasses::Reference(ModuleID module, mdTypeRef token, uint32_t depth)
{
    auto found = modules_.find(module);
    if (depth > MaxTypeResolutionDepth || found == modules_.end()) return {};
    wchar_t name[MetadataTypeNameCapacity]{};
    ULONG length = 0;
    mdToken scope = 0;
    if (FAILED(found->second.metadata->GetTypeRefProps(token, &scope, name, _countof(name), &length)) ||
        !length || length > _countof(name)) return {};
    if (!scope || TypeFromToken(scope) == mdtModule) return Named(module, name, 0, depth + 1);
    if (TypeFromToken(scope) == mdtAssemblyRef)
        return Named(Assembly(module, scope), name, 0, depth + 1);
    if (TypeFromToken(scope) == mdtTypeRef)
    {
        auto [owner, enclosing] = Reference(module, scope, depth + 1);
        return enclosing ? Named(owner, name, enclosing, depth + 1) : Definition{};
    }
    if (TypeFromToken(scope) != mdtModuleRef) return {};
    wchar_t file[MetadataScopeNameCapacity]{};
    if (FAILED(found->second.metadata->GetModuleRefProps(scope, file, _countof(file), &length)) ||
        !length || length > _countof(file)) return {};
    ModuleID matched = 0;
    for (const auto& [candidate, entry] : modules_)
        if (entry.assembly == found->second.assembly && !_wcsicmp(entry.name.c_str(), file))
        {
            if (matched) return {};
            matched = candidate;
        }
    return Named(matched, name, 0, depth + 1);
}

void ManagedClasses::Observe(ICorProfilerInfo2* profiler, ClassID type)
{
    // Keep only classes the CLR has already loaded; resolving a signature must not load target code.
    std::vector<ClassID> pending{type};
    std::set<ClassID> visited;
    while (!pending.empty() && visited.size() < MaxClassVisitCount)
    {
        auto current = pending.back();
        pending.pop_back();
        if (!current || !visited.insert(current).second) continue;
        ModuleID module = 0;
        mdTypeDef token = 0;
        std::array<ClassID, MaxGenericArguments> arguments{};
        ULONG32 count = 0;
        if (FAILED(profiler->GetClassIDInfo2(current, &module, &token, nullptr,
            static_cast<ULONG>(arguments.size()), &count, arguments.data())) || !module || !token ||
            count > arguments.size()) continue;
        pending.insert(pending.end(), arguments.begin(), arguments.begin() + count);
        ObserveModule(profiler, module);
        std::lock_guard lock(mutex_);
        if (classes_.size() < MaxObservedClasses)
            classes_[{module, token, {arguments.begin(), arguments.begin() + count}}] = current;
    }
}

void ManagedClasses::Forget(ClassID type)
{
    std::lock_guard lock(mutex_);
    std::erase_if(classes_, [type](const auto& entry) { return entry.second == type; });
}

ClassID ManagedClasses::Resolve(ICorProfilerInfo2* profiler, ModuleID module, mdToken token,
    std::span<const ClassID> arguments)
{
    ObserveModule(profiler, module);
    std::lock_guard lock(mutex_);
    if (TypeFromToken(token) == mdtTypeRef) std::tie(module, token) = Reference(module, token, 0);
    if (!module || TypeFromToken(token) != mdtTypeDef) return 0;
    auto found = classes_.find({module, token, {arguments.begin(), arguments.end()}});
    return found == classes_.end() ? 0 : found->second;
}

ClassID ManagedClasses::Primitive(const wchar_t* name)
{
    std::lock_guard lock(mutex_);
    ClassID matched = 0;
    for (const auto& [module, entry] : modules_)
    {
        mdTypeDef token = 0;
        if (!entry.coreLibrary || FAILED(entry.metadata->FindTypeDefByName(name, 0, &token))) continue;
        auto found = classes_.find({module, token, {}});
        if (found == classes_.end()) continue;
        if (matched && matched != found->second) return 0;
        matched = found->second;
    }
    return matched;
}

ModuleID ManagedClasses::CoreLibrary()
{
    std::lock_guard lock(mutex_);
    ModuleID matched = 0;
    for (const auto& [module, entry] : modules_)
    {
        mdTypeDef array = 0;
        if (!entry.coreLibrary || FAILED(entry.metadata->FindTypeDefByName(L"System.Array", 0, &array))) continue;
        if (matched) return 0;
        matched = module;
    }
    return matched;
}

struct ManagedLayoutReader
{
    ICorProfilerInfo2* profiler;
    ManagedClasses* classes;
    std::map<ClassID, ManagedType> types;
    std::map<ClassID, nlohmann::json> layouts;
    ManagedType Type(ClassID identity, uint32_t depth = 0);
    std::string Describe(const ManagedMethod& method) const;
};

struct ManagedLayoutContext
{
    ManagedLayoutReader& reader;
    ModuleID module;
    ClassID owner;
    std::span<const ClassID> classArguments, methodArguments;
};

bool DecodeManagedMethod(IMetaDataImport* metadata, const std::wstring& path, mdMethodDef token,
    ManagedMethod& method, std::vector<BYTE>* resultSignature, ManagedLayoutContext* context);

class SignatureReader : public ManagedSignatureCursor
{
public:
    SignatureReader(IMetaDataImport* metadata, PCCOR_SIGNATURE signature, ULONG size,
        ManagedLayoutContext* context = nullptr)
        : ManagedSignatureCursor({signature, size}), metadata_(metadata), context_(context) {}

    ManagedType Type(uint32_t depth = 0)
    {
        if (depth > MaxSignatureDepth) throw std::runtime_error("Managed signature nesting exceeded.");
        ManagedType type;
        type.element = static_cast<CorElementType>(Byte());
        switch (type.element)
        {
        case ELEMENT_TYPE_VOID: type.name = L"void"; break;
        case ELEMENT_TYPE_BOOLEAN: type.name = L"bool"; type.bytes = 1; break;
        case ELEMENT_TYPE_CHAR: type.name = L"char"; type.bytes = 2; break;
        case ELEMENT_TYPE_I1: type.name = L"int8"; type.bytes = 1; break;
        case ELEMENT_TYPE_U1: type.name = L"uint8"; type.bytes = 1; break;
        case ELEMENT_TYPE_I2: type.name = L"int16"; type.bytes = 2; break;
        case ELEMENT_TYPE_U2: type.name = L"uint16"; type.bytes = 2; break;
        case ELEMENT_TYPE_I4: type.name = L"int32"; type.bytes = 4; break;
        case ELEMENT_TYPE_U4: type.name = L"uint32"; type.bytes = 4; break;
        case ELEMENT_TYPE_I8: type.name = L"int64"; type.bytes = 8; break;
        case ELEMENT_TYPE_U8: type.name = L"uint64"; type.bytes = 8; break;
        case ELEMENT_TYPE_R4: type.name = L"float32"; type.bytes = 4; break;
        case ELEMENT_TYPE_R8: type.name = L"float64"; type.bytes = 8; break;
        case ELEMENT_TYPE_I: type.name = L"nint"; type.bytes = sizeof(void*); break;
        case ELEMENT_TYPE_U: type.name = L"nuint"; type.bytes = sizeof(void*); break;
        case ELEMENT_TYPE_STRING: type.name = L"string"; type.bytes = sizeof(void*); break;
        case ELEMENT_TYPE_OBJECT: type.name = L"object"; type.bytes = sizeof(void*); break;
        case ELEMENT_TYPE_CLASS:
        case ELEMENT_TYPE_VALUETYPE:
        {
            auto token = Number();
            type.name = TokenName(token);
            type.bytes = type.element == ELEMENT_TYPE_CLASS ? sizeof(void*) : 0;
            if (auto identity = Resolve(token, {}))
                if (auto loaded = context_->reader.Type(identity, depth + 1); !loaded.name.empty())
                    type = std::move(loaded);
            break;
        }
        case ELEMENT_TYPE_BYREF:
            type = Type(depth + 1);
            type.byReference = true;
            type.name += L"&";
            type.referencedBytes = type.bytes;
            type.bytes = sizeof(void*);
            break;
        case ELEMENT_TYPE_PTR:
            type.name = Type(depth + 1).name + L"*";
            type.bytes = sizeof(void*);
            break;
        case ELEMENT_TYPE_SZARRAY:
        {
            auto element = Type(depth + 1);
            type.name = element.name + L"[]";
            type.elementBytes = element.element == ELEMENT_TYPE_VALUETYPE ? 0 : element.bytes;
            type.elementIdentity = element.identity;
            type.arrayRank = 1;
            type.bytes = sizeof(void*);
            break;
        }
        case ELEMENT_TYPE_ARRAY:
        {
            auto element = Type(depth + 1);
            auto rank = Number();
            auto sizes = Number();
            if (rank > MaxArrayRank || sizes > MaxArrayRank) throw std::runtime_error("Invalid managed array signature.");
            for (uint32_t index = 0; index < sizes; ++index) Number();
            auto bounds = Number();
            if (bounds > MaxArrayRank) throw std::runtime_error("Invalid managed array signature.");
            for (uint32_t index = 0; index < bounds; ++index) Number();
            type.name = element.name + L"[" + std::wstring(rank ? rank - 1 : 0, L',') + L"]";
            type.elementBytes = element.element == ELEMENT_TYPE_VALUETYPE ? 0 : element.bytes;
            type.elementIdentity = element.identity;
            type.arrayRank = rank;
            type.bytes = sizeof(void*);
            break;
        }
        case ELEMENT_TYPE_VAR:
        case ELEMENT_TYPE_MVAR:
        {
            auto index = Number();
            type.name = (type.element == ELEMENT_TYPE_VAR ? L"!" : L"!!") + std::to_wstring(index);
            if (context_)
            {
                auto arguments = type.element == ELEMENT_TYPE_VAR ?
                    context_->classArguments : context_->methodArguments;
                if (index < arguments.size())
                    if (auto loaded = context_->reader.Type(arguments[index], depth + 1); !loaded.name.empty())
                        type = std::move(loaded);
            }
            break;
        }
        case ELEMENT_TYPE_GENERICINST:
        {
            auto category = Byte();
            auto token = Number();
            type.name = TokenName(token) + L"<";
            auto count = Number();
            if (count > MaxGenericArguments) throw std::runtime_error("Invalid managed generic signature.");
            std::vector<ClassID> arguments;
            for (uint32_t index = 0; index < count; ++index)
            {
                if (index) type.name += L", ";
                auto argument = Type(depth + 1);
                type.name += argument.name;
                arguments.push_back(argument.identity);
            }
            type.name += L">";
            type.bytes = category == ELEMENT_TYPE_CLASS ? sizeof(void*) : 0;
            if (std::all_of(arguments.begin(), arguments.end(), [](ClassID value) { return value != 0; }))
                if (auto identity = Resolve(token, arguments))
                    if (auto loaded = context_->reader.Type(identity, depth + 1); !loaded.name.empty())
                        type = std::move(loaded);
            break;
        }
        case ELEMENT_TYPE_CMOD_OPT:
        case ELEMENT_TYPE_CMOD_REQD:
            Number();
            return Type(depth + 1);
        case ELEMENT_TYPE_PINNED:
            return Type(depth + 1);
        case ELEMENT_TYPE_TYPEDBYREF:
            type.name = L"typedref";
            break;
        default:
            throw std::runtime_error("Unsupported managed signature element.");
        }
        if (type.name == L"System.Array") type.arrayRank = UINT32_MAX;
        if (context_ && !type.identity && !type.byReference)
        {
            // Primitive generic arguments use the core library's already observed class identities.
            for (const auto& [element, name] : ManagedPrimitives)
            {
                if (element == type.element) type.identity = context_->reader.classes->Primitive(name);
            }
        }
        return type;
    }

private:
    ClassID Resolve(uint32_t encoded, std::span<const ClassID> arguments)
    {
        if (!context_ || (encoded & TypeDefOrRefTagMask) > 1) return 0;
        auto token = TokenFromRid(encoded >> TypeDefOrRefTagBits,
            (encoded & TypeDefOrRefTagMask) == 0 ? mdtTypeDef : mdtTypeRef);
        return context_->reader.classes->Resolve(context_->reader.profiler, context_->module, token, arguments);
    }


    std::wstring TokenName(uint32_t encoded)
    {
        const uint32_t kinds[] = {mdtTypeDef, mdtTypeRef, mdtTypeSpec};
        auto tag = encoded & TypeDefOrRefTagMask;
        if (tag > 2) throw std::runtime_error("Invalid managed type token.");
        auto token = TokenFromRid(encoded >> TypeDefOrRefTagBits, kinds[tag]);
        wchar_t name[MetadataTypeNameCapacity]{};
        ULONG length = 0;
        HRESULT result = E_FAIL;
        if (tag == 0) result = metadata_->GetTypeDefProps(token, name, _countof(name), &length, nullptr, nullptr);
        if (tag == 1) result = metadata_->GetTypeRefProps(token, nullptr, name, _countof(name), &length);
        return SUCCEEDED(result) ? name : L"type(" + std::to_wstring(token) + L")";
    }

    IMetaDataImport* metadata_;
    ManagedLayoutContext* context_;
};

ManagedType ManagedLayoutReader::Type(ClassID identity, uint32_t depth)
{
    if (!identity || depth > MaxLayoutDepth) return {};
    if (auto found = types.find(identity); found != types.end()) return found->second;

    // Class identities come from load notifications or the current method's loaded generic context.
    ModuleID module = 0;
    mdTypeDef token = 0;
    std::array<ClassID, MaxGenericArguments> arguments{};
    ULONG32 count = 0;
    ComPtr<IMetaDataImport> metadata;
    wchar_t name[MetadataTypeNameCapacity]{};
    mdToken base = 0;
    if (FAILED(profiler->GetClassIDInfo2(identity, &module, &token, nullptr,
        static_cast<ULONG>(arguments.size()), &count, arguments.data())) || !module || !token ||
        count > arguments.size() || FAILED(profiler->GetModuleMetaData(module, ofRead, IID_IMetaDataImport,
            reinterpret_cast<IUnknown**>(metadata.GetAddressOf()))) ||
        FAILED(metadata->GetTypeDefProps(token, name, _countof(name), nullptr, nullptr, &base))) return {};
    const bool valueType = IsValueTypeBase(metadata.Get(), base);
    auto& type = types[identity];
    type.identity = identity;
    type.name = name;
    type.element = valueType ? ELEMENT_TYPE_VALUETYPE : ELEMENT_TYPE_CLASS;
    type.bytes = valueType ? 0 : sizeof(void*);
    for (const auto& [element, primitive] : ManagedPrimitives)
        if (!wcscmp(name, primitive))
        {
            const BYTE signature = static_cast<BYTE>(element);
            type = SignatureReader(metadata.Get(), &signature, 1).Type();
            type.identity = identity;
            return type;
        }
    if (count)
    {
        type.name += L"<";
        for (ULONG index = 0; index < count; ++index)
        {
            if (index) type.name += L", ";
            auto argument = Type(arguments[index], depth + 1);
            type.name += argument.name.empty() ? L"?" : argument.name;
        }
        type.name += L">";
    }
    if (!valueType) return type;

    // Offsets describe unboxed data; the reported class size can include a boxed object's runtime header.
    std::array<COR_FIELD_OFFSET, MaxClassFields> offsets{};
    ULONG fields = 0, bytes = 0;
    if (FAILED(profiler->GetClassLayout(identity, offsets.data(), static_cast<ULONG>(offsets.size()),
        &fields, &bytes)) || fields > offsets.size()) return type;
    ManagedLayoutContext context{*this, module, identity, {arguments.data(), count}, {}};
    uint32_t extent = 0;
    auto members = nlohmann::json::array();
    for (ULONG index = 0; index < fields; ++index)
    {
        PCCOR_SIGNATURE signature = nullptr;
        ULONG signatureBytes = 0;
        wchar_t fieldName[MetadataShortNameCapacity]{};
        if (FAILED(metadata->GetFieldProps(offsets[index].ridOfField, nullptr, fieldName,
            _countof(fieldName), nullptr, nullptr, &signature, &signatureBytes, nullptr, nullptr, nullptr)))
            return type;
        SignatureReader reader(metadata.Get(), signature, signatureBytes, &context);
        if (reader.Number() != IMAGE_CEE_CS_CALLCONV_FIELD) return type;
        auto field = reader.Type(depth + 1);
        if (!field.bytes || offsets[index].ulOffset > UINT32_MAX - field.bytes) return type;
        extent = std::max<uint32_t>(extent, offsets[index].ulOffset + field.bytes);
        members.push_back({Utf8(fieldName), Utf8(field.name), offsets[index].ulOffset, field.bytes,
            field.byReference ? ClassID{} : field.identity});
    }
    type.bytes = extent;
    layouts[identity] = {{"Name", Utf8(type.name)}, {"Size", type.bytes}, {"Fields", std::move(members)}};
    return type;
}

std::string ManagedLayoutReader::Describe(const ManagedMethod& method) const
{
    auto definitions = nlohmann::json::array(), arguments = nlohmann::json::array();
    std::map<ClassID, uint32_t> indexes;
    for (const auto& [identity, layout] : layouts)
        indexes[identity] = static_cast<uint32_t>(indexes.size());
    for (const auto& [identity, layout] : layouts)
    {
        // Field references preserve identity when several assemblies define the same type name.
        auto definition = layout;
        for (auto& field : definition["Fields"])
        {
            auto found = indexes.find(field[4].get<ClassID>());
            if (found == indexes.end()) field.erase(field.begin() + 4);
            else field[4] = found->second;
        }
        definitions.push_back(std::move(definition));
    }
    bool used = false;
    auto reference = [&](const ManagedType& type) -> nlohmann::json
    {
        if (type.arrayRank)
        {
            if (auto found = indexes.find(type.elementIdentity); found != indexes.end())
            {
                used = true;
                return {{"Element", found->second}, {"Rank", type.arrayRank}};
            }
            return nullptr;
        }
        if (auto found = indexes.find(type.identity); found != indexes.end())
        {
            used = true;
            return found->second;
        }
        return nullptr;
    };
    for (const auto& argument : method.arguments) arguments.push_back(reference(argument));
    auto returned = reference(method.result);
    if (!used) return {};
    auto descriptor = nlohmann::json{{"Types", std::move(definitions)}, {"Arguments", std::move(arguments)},
        {"Result", returned}}.dump();
    if (descriptor.size() > UINT32_MAX) throw std::length_error("Managed layout exceeds the transport size.");
    return descriptor;
}

bool FrameworkModule(const std::wstring& path)
{
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), towlower);
    auto separator = lower.find_last_of(L"\\/");
    auto file = lower.substr(separator == std::wstring::npos ? 0 : separator + 1);

    // Framework identities include self-contained deployments whose files are beside the application.
    return file == L"mscorlib.dll" || file == L"system.private.corelib.dll" || file == L"system.dll" ||
        file == L"netstandard.dll" || file.starts_with(L"system.") || file.starts_with(L"microsoft.") ||
        file == L"windowsbase.dll" || file.starts_with(L"presentationframework") || file == L"presentationcore.dll";
}

bool FrameworkIdentity(IMetaDataImport* metadata)
{
    ComPtr<IMetaDataAssemblyImport> assemblies;
    mdAssembly assembly = 0;
    const void* publicKey = nullptr;
    ULONG keyBytes = 0;
    DWORD flags = 0;
    if (FAILED(metadata->QueryInterface(IID_IMetaDataAssemblyImport,
        reinterpret_cast<void**>(assemblies.GetAddressOf()))) ||
        FAILED(assemblies->GetAssemblyFromScope(&assembly)) ||
        FAILED(assemblies->GetAssemblyProps(assembly, &publicKey, &keyBytes, nullptr, nullptr, 0,
            nullptr, nullptr, &flags)) || !publicKey || !keyBytes) return false;

    // Framework names alone are insufficient: application assemblies can use the same file names.
    uint64_t token = 0;
    if (!ReadPublicKeyToken(publicKey, keyBytes, flags, token)) return false;
    return token == 0xB77A5C561934E089 || token == 0xB03F5F7F11D50A3A || token == 0x7CEC85D7BEA7798E ||
        token == 0xCC7B13FFCD2DDD51 || token == 0x31BF3856AD364E35 || token == 0xADB9793829DDAE60;
}

bool ReadManagedMethod(ICorProfilerInfo2* profiler, FunctionID function, ManagedMethod& method,
    ManagedClasses& classes, bool resolveGenerics)
{
    ClassID owner = 0;
    ModuleID module = 0;
    mdToken token = 0;
    std::array<ClassID, MaxGenericArguments> methodArguments{}, classArguments{};
    ULONG32 methods = 0, parameters = 0;
    if (FAILED(profiler->GetFunctionInfo2(function, 0, &owner, &module, &token,
        static_cast<ULONG>(methodArguments.size()), &methods, methodArguments.data())) || !module ||
        methods > methodArguments.size()) return false;
    if (!ReadManagedMethod(profiler, module, token, method)) return false;
    classes.Observe(profiler, owner);
    for (ULONG index = 0; index < methods; ++index) classes.Observe(profiler, methodArguments[index]);
    if (owner && (FAILED(profiler->GetClassIDInfo2(owner, nullptr, nullptr, nullptr,
        static_cast<ULONG>(classArguments.size()), &parameters, classArguments.data())) ||
        parameters > classArguments.size())) parameters = 0;
    method.function = function;
    if (!resolveGenerics && (parameters || methods)) return true;
    ComPtr<IMetaDataImport> metadata;
    if (FAILED(profiler->GetModuleMetaData(module, ofRead, IID_IMetaDataImport,
        reinterpret_cast<IUnknown**>(metadata.GetAddressOf())))) return false;

    // Resolve only observed classes, preserving raw signatures when a loaded instantiation is unavailable.
    ManagedLayoutReader layouts{profiler, &classes};
    auto valueArguments = [&](std::span<const ClassID> arguments)
    {
        return std::all_of(arguments.begin(), arguments.end(), [&](ClassID identity)
        {
            auto type = layouts.Type(identity);
            return type.element != ELEMENT_TYPE_END && type.element != ELEMENT_TYPE_CLASS &&
                type.element != ELEMENT_TYPE_OBJECT && type.element != ELEMENT_TYPE_STRING;
        });
    };

    // Shared reference instantiations require a live frame to identify their concrete generic arguments.
    if (!valueArguments({classArguments.data(), parameters})) { parameters = 0; owner = 0; }
    if (!valueArguments({methodArguments.data(), methods})) methods = 0;
    ManagedLayoutContext context{layouts, module, owner,
        {classArguments.data(), parameters}, {methodArguments.data(), methods}};
    ManagedMethod decoded;
    if (!DecodeManagedMethod(metadata.Get(), method.moduleName, token, decoded, nullptr, &context)) return false;
    decoded.module = module;
    decoded.function = function;
    decoded.layout = layouts.Describe(decoded);
    method = std::move(decoded);
    return true;
}

bool ReadManagedMethod(ICorProfilerInfo2* profiler, ModuleID module, mdMethodDef token, ManagedMethod& method)
{
    wchar_t path[ExtendedPathCapacity]{};
    ULONG pathLength = 0;
    AssemblyID assembly = 0;
    if (FAILED(profiler->GetModuleInfo(module, nullptr, _countof(path), &pathLength, path, &assembly))) return false;
    if (!FrameworkModule(path)) return false;

    // Resolve names and signatures once, before installing per-call callbacks for this function.
    ComPtr<IMetaDataImport> metadata;
    if (FAILED(profiler->GetModuleMetaData(module, ofRead, IID_IMetaDataImport,
        reinterpret_cast<IUnknown**>(metadata.GetAddressOf())))) return false;
    if (!FrameworkIdentity(metadata.Get())) return false;
    if (!ReadManagedMethod(metadata.Get(), path, token, method)) return false;
    method.module = module;
    return true;
}

bool ReadManagedMethod(IMetaDataImport* metadata, const std::wstring& path, mdMethodDef token, ManagedMethod& method,
    std::vector<BYTE>* resultSignature)
{
    return DecodeManagedMethod(metadata, path, token, method, resultSignature, nullptr);
}

bool DecodeManagedMethod(IMetaDataImport* metadata, const std::wstring& path, mdMethodDef token,
    ManagedMethod& method, std::vector<BYTE>* resultSignature, ManagedLayoutContext* context)
{
    mdTypeDef declaringType = 0;
    wchar_t methodName[MetadataTypeNameCapacity]{}, typeName[MetadataTypeNameCapacity]{};
    ULONG nameLength = 0;
    DWORD attributes = 0;
    mdToken baseType = 0;
    PCCOR_SIGNATURE signature = nullptr;
    ULONG signatureSize = 0;
    if (FAILED(metadata->GetMethodProps(token, &declaringType, methodName, _countof(methodName), &nameLength,
        &attributes, &signature, &signatureSize, nullptr, nullptr))) return false;
    if (FAILED(metadata->GetTypeDefProps(declaringType, typeName, _countof(typeName), &nameLength,
        nullptr, &baseType))) return false;
    const bool valueType = IsValueTypeBase(metadata, baseType);
    method.token = token;
    auto separator = path.find_last_of(L"\\/");
    method.moduleName = path.substr(separator == std::wstring::npos ? 0 : separator + 1);
    method.name = std::wstring(typeName) + L"." + methodName;
    try
    {
        SignatureReader reader(metadata, signature, signatureSize, context);
        auto convention = reader.Number();
        if (convention & IMAGE_CEE_CS_CALLCONV_GENERIC) reader.Number();
        auto count = reader.Number();
        if (count > MaxMethodParameters) return false;
        auto start = reader.Position();
        method.result = reader.Type();
        if (resultSignature) resultSignature->assign(start, reader.Position());
        if (!(attributes & mdStatic))
        {
            auto receiver = std::wstring(typeName) + (valueType ? L"&" : L"");
            ManagedType self{valueType ? ELEMENT_TYPE_VALUETYPE : ELEMENT_TYPE_CLASS,
                sizeof(void*), 0, valueType, receiver};
            if (context && context->owner)
            {
                auto loaded = context->reader.Type(context->owner);
                self.identity = loaded.identity;
                self.referencedBytes = valueType ? loaded.bytes : 0;
                if (!loaded.name.empty()) self.name = loaded.name + (valueType ? L"&" : L"");
            }
            if (self.name == L"System.Array") self.arrayRank = UINT32_MAX;
            method.arguments.push_back(self);
            method.parameters = L"this: " + self.name;
        }
        std::wstring overload = L"(";
        for (uint32_t index = 0; index < count; ++index)
        {
            auto parameterType = reader.Type();
            if (index) overload += L", ";
            overload += parameterType.name;
            mdParamDef parameter = 0;
            wchar_t parameterName[MetadataParameterNameCapacity]{};
            if (SUCCEEDED(metadata->GetParamForMethodIndex(token, index + 1, &parameter)))
            {
                metadata->GetParamProps(parameter, nullptr, nullptr, parameterName, _countof(parameterName),
                    &nameLength, nullptr, nullptr, nullptr, nullptr);
            }
            if (!method.parameters.empty()) method.parameters += L", ";
            method.parameters += parameterName[0] ? parameterName : L"arg" + std::to_wstring(index);
            method.parameters += L": " + parameterType.name;
            method.arguments.push_back(std::move(parameterType));
        }
        method.name += overload + L")";
        method.parameters += L" -> " + method.result.name;
        method.decodedArguments = std::all_of(method.arguments.begin(), method.arguments.end(),
            [](const ManagedType& value) { return value.bytes != 0; });
    }
    catch (const std::exception&)
    {
        method.arguments.clear();
        if (resultSignature) resultSignature->clear();
        method.parameters = L"Raw CLR argument regions; signature decoding unavailable";
    }
    return true;
}
}
