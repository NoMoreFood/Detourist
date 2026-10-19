#include "TraceStore.h"
#include <dbghelp.h>
#include <algorithm>
#include <filesystem>
#include <mutex>
#include <unordered_map>

namespace Detourist
{
bool LocalSymbolDirectory(const std::wstring& path)
{
    if (path.size() < 3 || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/') ||
        path.find_first_of(L"*?;") != std::wstring::npos) return false;
    auto root = path.substr(0, 3);
    const auto drive = GetDriveTypeW(root.c_str());
    return drive != DRIVE_REMOTE && drive != DRIVE_UNKNOWN;
}

class SymbolResolver
{
public:
    ~SymbolResolver()
    {
        if (initialized_) SymCleanup(token_.get());
    }

    void Configure(const std::vector<std::wstring>& directories)
    {
        std::vector<std::wstring> paths;
        for (const auto& path : directories)
        {
            auto full = std::filesystem::absolute(path).wstring();
            if (full.size() < 3 || full[1] != L':' || (full[2] != L'\\' && full[2] != L'/') ||
                full.find_first_of(L"*?;") != std::wstring::npos)
                throw std::runtime_error("Choose local symbol folders.");
            if (std::find(paths.begin(), paths.end(), full) == paths.end()) paths.push_back(std::move(full));
        }
        std::lock_guard lock(mutex_);
        Clear();
        directories_ = std::move(paths);
    }

    ResolvedSymbol Resolve(const ModuleRow& module, uint64_t address)
    {
        const auto& identity = module.identity;
        if (!(identity.flags & PdbIdentityValid)) return {.state = "identity_unavailable"};
        if (address < module.base || address - module.base >= module.size) return {.state = "address_unavailable"};
        auto name = Wide(identity.pdbName);
        if (name.empty() || name.find_first_of(L"\\/:*?;") != std::wstring::npos)
            return {.state = "identity_unavailable"};
        std::lock_guard lock(mutex_);

        // DbgHelp has process-wide state; one serialized session handles only explicitly selected local PDB files.
        if (!initialized_)
        {
            token_.reset(CreateEventW(nullptr, FALSE, FALSE, nullptr));
            SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_EXACT_SYMBOLS | SYMOPT_IGNORE_NT_SYMPATH |
                SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS | SYMOPT_NO_IMAGE_SEARCH |
                SYMOPT_IGNORE_CVREC | SYMOPT_DISABLE_SYMSRV_AUTODETECT | SYMOPT_INCLUDE_32BIT_MODULES);
            initialized_ = token_ && SymInitializeW(token_.get(), L"", FALSE);
            if (!initialized_) return {.state = "resolver_unavailable"};
        }
        auto key = module.path;
        key.push_back('\0');
        key.append(reinterpret_cast<const char*>(&identity), sizeof(identity));
        auto loaded = images_.find(key);
        if (loaded == images_.end())
        {
            if (images_.size() >= MaxLoadedSymbolImages) Clear();
            loaded = images_.emplace(std::move(key), Load(module, name)).first;
        }
        auto& image = loaded->second;
        if (!image.base) return {.state = image.state};
        const auto offset = address - module.base;
        if (auto cached = image.addresses.find(offset); cached != image.addresses.end()) return cached->second;
        ResolvedSymbol result{.pdb = image.pdb, .state = "symbol_unavailable"};
        alignas(SYMBOL_INFOW) std::byte storage[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t)]{};
        auto symbol = reinterpret_cast<SYMBOL_INFOW*>(storage);
        symbol->SizeOfStruct = sizeof(*symbol);
        symbol->MaxNameLen = MAX_SYM_NAME;
        if (SymFromAddrW(token_.get(), image.base + offset, &result.displacement, symbol) &&
            symbol->ModBase == image.base && symbol->Address >= image.base &&
            symbol->Address - image.base < module.size)
        {
            result.name = Utf8(std::wstring(symbol->Name, std::min<DWORD>(symbol->NameLen, MAX_SYM_NAME)));
            result.state = "resolved";
            IMAGEHLP_LINEW64 line{};
            line.SizeOfStruct = sizeof(line);
            DWORD displacement = 0;
            if (SymGetLineFromAddrW64(token_.get(), image.base + offset, &displacement, &line) && line.FileName)
            {
                result.source = Utf8(line.FileName);
                result.line = line.LineNumber;
            }
        }
        if (image.addresses.size() >= MaxCachedSymbolAddresses) image.addresses.clear();
        image.addresses.emplace(offset, result);
        return result;
    }

private:
    struct Image
    {
        uint64_t base = 0;
        std::string pdb, state;
        std::unordered_map<uint64_t, ResolvedSymbol> addresses;
    };

    void Clear()
    {
        for (const auto& [key, image] : images_)
            if (image.base) SymUnloadModule64(token_.get(), image.base);
        images_.clear();
    }

    Image Load(const ModuleRow& module, const std::wstring& name)
    {
        auto directories = directories_;
        auto parent = std::filesystem::path(Wide(module.path)).parent_path().wstring();
        if (LocalSymbolDirectory(parent)) directories.push_back(std::move(parent));
        const auto& identity = module.identity;
        wchar_t identifier[48]{};
        const auto& id = identity.pdb;
        swprintf_s(identifier, L"%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%lX",
            id.Data1, id.Data2, id.Data3, id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3],
            id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7], static_cast<unsigned long>(identity.pdbAge));
        std::wstring search;
        bool candidate = false;
        for (const auto& directory : directories)
        {
            if (!LocalSymbolDirectory(directory)) continue;
            for (const auto& path : {std::filesystem::path(directory),
                std::filesystem::path(directory) / name / identifier})
            {
                if (!search.empty()) search += L';';
                search += path.wstring();
                const auto attributes = GetFileAttributesW((path / name).c_str());
                candidate |= attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
            }
        }
        if (search.empty()) return {.state = "pdb_missing"};
        wchar_t found[ExtendedPathCapacity]{};
        auto signature = identity.pdb;
        if (!SymFindFileInPathW(token_.get(), search.c_str(), name.c_str(), &signature, identity.pdbAge,
            0, SSRVOPT_GUIDPTR, found, nullptr, nullptr))
            return {.state = candidate ? "pdb_mismatch" : "pdb_missing"};

        // Synthetic bases keep overlapping historical image lifetimes separate, even after the target exits.
        const auto base = nextBase_;
        nextBase_ += (uint64_t{identity.imageSize} + SyntheticBaseAlignment - 1) & ~(SyntheticBaseAlignment - 1);
        if (!identity.imageSize || !SymLoadModuleExW(token_.get(), nullptr, found, nullptr,
            base, identity.imageSize, nullptr, 0)) return {.state = "pdb_unavailable"};
        IMAGEHLP_MODULEW64 information{};
        information.SizeOfStruct = sizeof(information);
        // Match the trace's GUID and age independently of DbgHelp's image-match flag for direct PDB loads.
        if (!SymGetModuleInfoW64(token_.get(), base, &information) || information.DbgUnmatched ||
            (information.SymType != SymPdb && information.SymType != SymDia) ||
            information.PdbSig70 != identity.pdb || information.PdbAge != identity.pdbAge)
        {
            SymUnloadModule64(token_.get(), base);
            return {.state = "pdb_mismatch"};
        }
        return {.base = base, .pdb = Utf8(found), .state = "loaded"};
    }

    static constexpr size_t MaxLoadedSymbolImages = 128;
    static constexpr size_t MaxCachedSymbolAddresses = 65536;
    static constexpr uint64_t InitialSyntheticBase = 0x100000000;
    static constexpr uint64_t SyntheticBaseAlignment = 0x10000;
    std::mutex mutex_;
    Handle token_;
    bool initialized_ = false;
    uint64_t nextBase_ = InitialSyntheticBase;
    std::vector<std::wstring> directories_;
    std::unordered_map<std::string, Image> images_;
};

SymbolResolver& Symbols()
{
    static SymbolResolver resolver;
    return resolver;
}

ResolvedSymbol ResolveSymbol(const ModuleRow& module, uint64_t address) { return Symbols().Resolve(module, address); }
void SetSymbolDirectories(const std::vector<std::wstring>& directories) { Symbols().Configure(directories); }
}
