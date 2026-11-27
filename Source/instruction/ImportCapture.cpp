#include "InstructionCapture.h"
#include <delayimp.h>
#include <array>
#include <cstring>

namespace Detourist
{
extern uint32_t NextExportId;
app_pc ForwardAddress(const char* text, uint32_t depth);
bool NonImageExportAddress(app_pc address);

struct ImportOrigin
{
    uint64_t caller, slot;
    app_pc importer, provider;
    InstructionDefinition definition;
    ImportOrigin* next;
};

constexpr uint32_t ImportBuckets = 512;
constexpr uint32_t NonImportBuckets = 2048;
constexpr DWORD MaxPeExports = 65536;
constexpr size_t MaxImportDescriptors = 4096;
constexpr uint64_t MaxImportThunks = 8192;
constexpr size_t MaxRuntimeFunctions = 1048576;
constexpr uint32_t MaxImportWrapperBytes = 512;
constexpr uint32_t MaxImportOrigins = 8192;
constexpr int XspRegisterIndex = 4;
constexpr int XbpRegisterIndex = 5;
struct NonImportCaller
{
    uint64_t caller;
    app_pc importer;
};
ImportOrigin* ImportOrigins[ImportBuckets]{};
NonImportCaller NonImportCallers[NonImportBuckets]{};
uint64_t ImportEpoch = 0;
uint32_t ImportOriginCount = 0;

bool ImportImageRead(const module_data_t& module, uint64_t rva, void* output, size_t bytes)
{
    auto extent = static_cast<uint64_t>(module.end - module.start);
    return rva < extent && bytes <= extent - rva &&
        ReadCaptureMemory(module.start + rva, output, bytes);
}

bool ImportImageHeaders(const module_data_t& module, IMAGE_NT_HEADERS& image)
{
    IMAGE_DOS_HEADER dos{};
    return ImportImageRead(module, 0, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 &&
           ImportImageRead(module, static_cast<uint32_t>(dos.e_lfanew), &image, sizeof(image)) &&
           image.Signature == IMAGE_NT_SIGNATURE &&
           image.FileHeader.Machine == (sizeof(void*) == 8 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386) &&
           image.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC &&
           image.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT;
}

bool ReadInstructionString(const char* source, char* output, size_t capacity)
{
    // Read one page span at a time so short image names do not require a probe for every character.
    const auto pageBytes = dr_page_size();
    for (size_t offset = 0; offset < capacity;)
    {
        auto bytes = std::min(capacity - offset, pageBytes - reinterpret_cast<uintptr_t>(source + offset) % pageBytes);
        if (!ReadCaptureMemory(source + offset, output + offset, bytes))
        {
            output[offset] = 0;
            return false;
        }
        if (memchr(output + offset, 0, bytes)) return output[0] != 0;
        offset += bytes;
    }
    if (capacity) output[capacity - 1] = 0;
    return false;
}

bool ImportImageString(const module_data_t& module, uint64_t rva, char* output, size_t capacity)
{
    auto extent = static_cast<uint64_t>(module.end - module.start);
    return rva < extent && ReadInstructionString(reinterpret_cast<const char*>(module.start + rva),
        output, static_cast<size_t>(std::min<uint64_t>(capacity, extent - rva)));
}

app_pc ImportExportAddress(const char* library, const char* name, DWORD ordinal, app_pc& provider)
{
    auto module = dr_lookup_module_by_name(library);
    if (!module) return nullptr;
    provider = module->start;
    IMAGE_NT_HEADERS image{};
    IMAGE_EXPORT_DIRECTORY exports{};
    DWORD function = 0;
    app_pc result = nullptr;
    if (ImportImageHeaders(*module, image))
    {
        const auto& directory = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (directory.VirtualAddress && directory.Size >= sizeof(exports) &&
            ImportImageRead(*module, directory.VirtualAddress, &exports, sizeof(exports)) &&
            exports.NumberOfFunctions <= MaxPeExports && exports.NumberOfNames <= MaxPeExports)
        {
            uint64_t index = UINT64_MAX;
            if (ordinal && ordinal >= exports.Base && ordinal - exports.Base < exports.NumberOfFunctions)
                index = ordinal - exports.Base;
            else if (!ordinal)
            {
                // PE export names are sorted; resolve a named import without rescanning the provider's table.
                DWORD first = 0, last = exports.NumberOfNames;
                while (first < last)
                {
                    auto candidate = first + (last - first) / 2;
                    DWORD nameRva = 0;
                    WORD ordinalIndex = 0;
                    char exportName[MaximumApiNameBytes]{};
                    if (!ImportImageRead(*module, uint64_t{exports.AddressOfNames} + candidate * sizeof(DWORD),
                            &nameRva, sizeof(nameRva)) || !ImportImageString(*module, nameRva,
                            exportName, std::size(exportName))) break;
                    auto compared = strcmp(exportName, name);
                    if (compared < 0) { first = candidate + 1; continue; }
                    if (compared > 0) { last = candidate; continue; }
                    if (ImportImageRead(*module, uint64_t{exports.AddressOfNameOrdinals} + candidate * sizeof(WORD),
                            &ordinalIndex, sizeof(ordinalIndex))) index = ordinalIndex;
                    break;
                }
            }
            if (index < exports.NumberOfFunctions && ImportImageRead(*module,
                uint64_t{exports.AddressOfFunctions} + index * sizeof(DWORD), &function, sizeof(function)) &&
                function && function <= UINTPTR_MAX - reinterpret_cast<uintptr_t>(module->start) &&
                (function < static_cast<uint64_t>(module->end - module->start) ||
                    NonImageExportAddress(module->start + function)))
            {
                result = module->start + function;
                if (function < static_cast<uint64_t>(module->end - module->start) && function >= directory.VirtualAddress &&
                    uint64_t{function} < uint64_t{directory.VirtualAddress} + directory.Size)
                {
                    char forwarder[512]{};
                    result = ImportImageString(*module, function, forwarder, std::size(forwarder)) ?
                        ForwardAddress(forwarder, 0) : nullptr;
                }
            }
        }
    }
    dr_free_module_data(module);
    return result;
}

bool ImportOrdinalName(const char* library, DWORD ordinal, char* name, size_t capacity)
{
    auto module = dr_lookup_module_by_name(library);
    if (!module) return false;
    IMAGE_NT_HEADERS image{};
    IMAGE_EXPORT_DIRECTORY exports{};
    bool found = false;
    if (ImportImageHeaders(*module, image))
    {
        const auto& directory = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (directory.VirtualAddress && directory.Size >= sizeof(exports) &&
            ImportImageRead(*module, directory.VirtualAddress, &exports, sizeof(exports)) &&
            exports.NumberOfFunctions <= MaxPeExports && exports.NumberOfNames <= MaxPeExports &&
            ordinal >= exports.Base && ordinal - exports.Base < exports.NumberOfFunctions)
        {
            auto selected = ordinal - exports.Base;

            // The requested import ordinal must identify one name in this exact loaded image.
            for (DWORD candidate = 0; candidate < exports.NumberOfNames; ++candidate)
            {
                WORD index = 0;
                if (!ImportImageRead(*module, uint64_t{exports.AddressOfNameOrdinals} + candidate * sizeof(WORD),
                    &index, sizeof(index)))
                {
                    found = false;
                    break;
                }
                if (index != selected) continue;
                DWORD nameRva = 0;
                if (found || !ImportImageRead(*module, uint64_t{exports.AddressOfNames} + candidate * sizeof(DWORD),
                    &nameRva, sizeof(nameRva)) || !ImportImageString(*module, nameRva, name, capacity))
                {
                    found = false;
                    break;
                }
                found = true;
            }
        }
    }
    dr_free_module_data(module);
    return found;
}

bool ImportSlotContract(const module_data_t& module, uint64_t slot, void* address,
    char* library, size_t libraryBytes, char* name, size_t nameBytes,
    const RuntimeExport*& runtime, Api& typed, app_pc& provider)
{
    IMAGE_NT_HEADERS image{};
    if (!ImportImageHeaders(module, image)) return false;
    for (bool delayed : {false, true})
    {
        uint32_t directoryIndex = delayed ? IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT : IMAGE_DIRECTORY_ENTRY_IMPORT;
        if (image.OptionalHeader.NumberOfRvaAndSizes <= directoryIndex) continue;
        const auto& directory = image.OptionalHeader.DataDirectory[directoryIndex];
        auto stride = delayed ? sizeof(ImgDelayDescr) : sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (!directory.VirtualAddress || directory.Size < stride || directory.Size / stride > MaxImportDescriptors)
            continue;
        auto descriptors = directory.Size / stride;
        for (uint32_t index = 0; index < descriptors; ++index)
        {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            auto rva = uint64_t{directory.VirtualAddress} + index * stride;
            if (delayed)
            {
                ImgDelayDescr delay{};
                if (!ImportImageRead(module, rva, &delay, sizeof(delay)) || !delay.rvaDLLName) break;
                if (delay.grAttrs != static_cast<DWORD>(dlattrRva)) continue;
                descriptor.Name = delay.rvaDLLName;
                descriptor.OriginalFirstThunk = delay.rvaINT;
                descriptor.FirstThunk = delay.rvaIAT;
            }
            else if (!ImportImageRead(module, rva, &descriptor, sizeof(descriptor)) || !descriptor.Name) break;
            if (!descriptor.OriginalFirstThunk || !descriptor.FirstThunk) continue;
            auto first = reinterpret_cast<uint64_t>(module.start) + descriptor.FirstThunk;
            if (slot < first || (slot - first) % sizeof(IMAGE_THUNK_DATA)) continue;
            auto selected = (slot - first) / sizeof(IMAGE_THUNK_DATA);
            if (selected >= MaxImportThunks) continue;
            IMAGE_THUNK_DATA thunk{};
            uint64_t entry = 0;
            for (; entry <= selected; ++entry)
            {
                if (!ImportImageRead(module, uint64_t{descriptor.OriginalFirstThunk} + entry * sizeof(thunk),
                        &thunk, sizeof(thunk)) || !thunk.u1.AddressOfData) break;
            }
            if (entry <= selected || !ImportImageString(module, descriptor.Name, library, libraryBytes)) continue;
            for (char* character = library; *character; ++character)
                if (*character >= 'A' && *character <= 'Z') *character = static_cast<char>(*character + 'a' - 'A');

            // Both the immutable import symbol and the currently resolved thunk must identify this exact export.
            DWORD ordinal = 0;
            if (IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal))
            {
                ordinal = static_cast<DWORD>(IMAGE_ORDINAL(thunk.u1.Ordinal));
                auto alias = InstructionTransport.catalog.OrdinalName(library, ordinal);
                if (alias)
                {
                    if (strlen(alias) >= nameBytes) return false;
                    memcpy(name, alias, strlen(alias) + 1);
                }
                else if (!ImportOrdinalName(library, ordinal, name, nameBytes)) return false;
            }
            else if (thunk.u1.AddressOfData > UINT32_MAX ||
                !ImportImageString(module, thunk.u1.AddressOfData + offsetof(IMAGE_IMPORT_BY_NAME, Name),
                    name, nameBytes)) return false;
            if (ImportExportAddress(library, name, ordinal, provider) != address) return false;
            runtime = RuntimeDefinitionFor(library, name);
            typed = FindExportType(library, name);
            return runtime && runtime->signature.supported || typed != Api::Count;
        }
    }
    return false;
}

bool ImportGuardDispatch(const module_data_t& module, uint64_t slot)
{
    IMAGE_NT_HEADERS image{};
    if (!ImportImageHeaders(module, image) ||
        image.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) return false;
    auto& directory = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    IMAGE_LOAD_CONFIG_DIRECTORY config{};
    constexpr auto minimum = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardCFDispatchFunctionPointer) + sizeof(void*);
    auto bytes = std::min<size_t>(directory.Size, sizeof(config));
    if (!directory.VirtualAddress || bytes < minimum ||
        !ImportImageRead(module, directory.VirtualAddress, &config, bytes) || config.Size < minimum) return false;
    return config.GuardCFDispatchFunctionPointer == slot ||
        config.Size >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardXFGDispatchFunctionPointer) + sizeof(void*) &&
        bytes >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardXFGDispatchFunctionPointer) + sizeof(void*) &&
        config.GuardXFGDispatchFunctionPointer == slot;
}

int ImportRegister(reg_id_t reg)
{
    constexpr reg_id_t registers[]{DR_REG_XAX, DR_REG_XCX, DR_REG_XDX, DR_REG_XBX, DR_REG_XSP, DR_REG_XBP,
        DR_REG_XSI, DR_REG_XDI,
#ifdef _WIN64
        DR_REG_R8, DR_REG_R9, DR_REG_R10, DR_REG_R11, DR_REG_R12, DR_REG_R13,
        DR_REG_R14, DR_REG_R15
#endif
    };
    for (uint32_t index = 0; index < std::size(registers); ++index)
        if (reg_overlap(reg, registers[index])) return static_cast<int>(index);
    return -1;
}

uint64_t ImportRegisterSlot(const module_data_t& module, uint64_t caller)
{
#ifndef _WIN64
    (void)module; (void)caller;
    return 0;
#else
    IMAGE_NT_HEADERS image{};
    if (!ImportImageHeaders(module, image) ||
        image.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION) return 0;
    auto& directory = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    auto rva = caller - 1 - reinterpret_cast<uint64_t>(module.start);
    auto count = directory.Size / sizeof(RUNTIME_FUNCTION);
    if (!directory.VirtualAddress || !count || count > MaxRuntimeFunctions) return 0;
    uint32_t low = 0, high = static_cast<uint32_t>(count);
    RUNTIME_FUNCTION function{};

    // Small unwind-bounded wrappers establish instruction boundaries and exclude alternate control-flow paths.
    while (low < high)
    {
        auto middle = low + (high - low) / 2;
        if (!ImportImageRead(module, uint64_t{directory.VirtualAddress} + middle * sizeof(function),
            &function, sizeof(function))) return 0;
        if (rva < function.BeginAddress) high = middle;
        else if (rva >= function.EndAddress) low = middle + 1;
        else break;
    }
    if (low >= high || function.EndAddress <= function.BeginAddress ||
        function.EndAddress - function.BeginAddress > MaxImportWrapperBytes) return 0;
    std::array<BYTE, MaxImportWrapperBytes + MaxX86InstructionBytes> code{};
    auto bytes = function.EndAddress - function.BeginAddress;
    if (!ImportImageRead(module, function.BeginAddress, code.data(), bytes)) return 0;
    auto context = dr_get_current_drcontext();
    std::array<uint64_t, 16> registers{};
    struct StackOrigin { reg_id_t base; int displacement; uint64_t slot; };
    std::array<StackOrigin, 32> stack{};
    uint32_t stackCount = 0;
    uint64_t result = 0;
    auto stackIndex = [&](opnd_t operand)
    {
        if (!opnd_is_base_disp(operand) || opnd_get_index(operand) != DR_REG_NULL ||
            (opnd_get_base(operand) != DR_REG_XSP && opnd_get_base(operand) != DR_REG_XBP)) return -1;
        for (uint32_t index = 0; index < stackCount; ++index)
            if (stack[index].base == opnd_get_base(operand) &&
                stack[index].displacement == opnd_get_disp(operand)) return static_cast<int>(index);
        return -1;
    };
    auto origin = [&](opnd_t operand)
    {
        if (opnd_get_size(operand) != OPSZ_8) return uint64_t{0};
        if (opnd_is_reg(operand))
        {
            auto index = ImportRegister(opnd_get_reg(operand));
            return index < 0 ? uint64_t{0} : registers[index];
        }
        if (InstructionStaticAddress(operand)) return reinterpret_cast<uint64_t>(opnd_get_addr(operand));
        auto index = stackIndex(operand);
        return index < 0 ? uint64_t{0} : stack[index].slot;
    };
    for (uint32_t offset = 0; offset < bytes;)
    {
        instr_t instruction;
        instr_init(context, &instruction);
        auto pc = module.start + function.BeginAddress + offset;
        auto next = decode_from_copy(context, code.data() + offset, pc, &instruction);
        auto length = next ? static_cast<uint32_t>(next - (code.data() + offset)) : 0;
        if (!length || length > bytes - offset)
        {
            instr_free(context, &instruction);
            return 0;
        }
        if (instr_is_return(&instruction) && !result)
        {
            instr_free(context, &instruction);
            return 0;
        }
        if (instr_is_cti(&instruction) && !instr_is_return(&instruction))
        {
            if (pc + length != reinterpret_cast<app_pc>(caller) || !instr_is_call_indirect(&instruction))
            {
                instr_free(context, &instruction);
                return 0;
            }
            auto target = instr_get_target(&instruction);
            if (InstructionStaticAddress(target) && ImportGuardDispatch(module,
                    reinterpret_cast<uint64_t>(opnd_get_addr(target)))) result = registers[0];
            else if (opnd_is_reg(target) || opnd_is_base_disp(target)) result = origin(target);
        }
        else if (!result)
        {
            auto move = (instr_get_opcode(&instruction) == OP_mov_ld ||
                instr_get_opcode(&instruction) == OP_mov_st) && instr_num_srcs(&instruction) == 1 &&
                instr_num_dsts(&instruction) == 1;
            auto value = move ? origin(instr_get_src(&instruction, 0)) : 0;
            for (int index = 0; index < instr_num_dsts(&instruction); ++index)
            {
                auto destination = instr_get_dst(&instruction, index);
                if (opnd_is_reg(destination))
                {
                    auto reg = ImportRegister(opnd_get_reg(destination));
                    if (reg >= 0) registers[reg] = opnd_get_size(destination) == OPSZ_8 ? value : 0;
                    if (reg == XspRegisterIndex || reg == XbpRegisterIndex) stackCount = 0;
                }
                else if (opnd_is_memory_reference(destination))
                {
                    if (opnd_is_base_disp(destination) && opnd_get_index(destination) == DR_REG_NULL &&
                        (opnd_get_base(destination) == DR_REG_XSP || opnd_get_base(destination) == DR_REG_XBP) &&
                        opnd_get_size(destination) == OPSZ_8)
                    {
                        for (uint32_t stored = 0; stored < stackCount; ++stored)
                        {
                            auto difference = int64_t{stack[stored].displacement} - opnd_get_disp(destination);
                            if (stack[stored].base != opnd_get_base(destination) ||
                                difference > -8 && difference < 8) stack[stored].slot = 0;
                        }
                        auto selected = stackIndex(destination);
                        if (selected < 0 && stackCount < stack.size()) selected = static_cast<int>(stackCount++);
                        if (selected >= 0)
                            stack[selected] = {opnd_get_base(destination), opnd_get_disp(destination), value};
                        else stackCount = 0;
                    }
                    else stackCount = 0;
                }
            }
        }
        instr_free(context, &instruction);
        offset += length;
    }
    return result;
#endif
}

InstructionDefinition* ResolveInstructionImport(InstructionDefinition* definition, uint64_t caller)
{
    // Direct IAT calls and linker import thunks retain the immutable symbol needed for folded exports.
    if (caller < MinimumUserAddress + 6) return definition;
    BYTE instruction[6]{};
    auto readable = ReadCaptureMemory(reinterpret_cast<void*>(caller - sizeof(instruction)), instruction,
        sizeof(instruction));
    int32_t displacement = 0;
    uint64_t slot = 0, thunk = 0;
    if (readable && instruction[0] == 0xff && instruction[1] == 0x15)
    {
        memcpy(&displacement, instruction + 2, sizeof(displacement));
        slot = sizeof(void*) == 8 ? static_cast<uint64_t>(static_cast<int64_t>(caller) + displacement) :
            static_cast<uint32_t>(displacement);
    }
    else if (ReadCaptureMemory(reinterpret_cast<void*>(caller - 5), instruction + 1, 5) && instruction[1] == 0xe8)
    {
        memcpy(&displacement, instruction + 2, sizeof(displacement));
        thunk = static_cast<uint64_t>(static_cast<int64_t>(caller) + displacement);
        if (!ReadCaptureMemory(reinterpret_cast<void*>(thunk), instruction, sizeof(instruction)) ||
            instruction[0] != 0xff || instruction[1] != 0x25) thunk = 0;
        else
        {
            memcpy(&displacement, instruction + 2, sizeof(displacement));
            slot = sizeof(void*) == 8
                       ? static_cast<uint64_t>(static_cast<int64_t>(thunk + sizeof(instruction)) + displacement)
                       : static_cast<uint32_t>(displacement);
        }
    }
    void* target = nullptr;
    auto direct = slot && ReadCaptureMemory(reinterpret_cast<void*>(slot), &target, sizeof(target)) &&
        target == definition->address;
    auto bucket = (caller >> 4) % ImportBuckets;
    auto nonImportBucket = (caller >> 2) % NonImportBuckets;
    dr_mutex_lock(DefinitionLock);
    auto epoch = ImportEpoch;
    for (auto origin = ImportOrigins[bucket]; origin; origin = origin->next)
    {
        if (origin->caller != caller || (direct && origin->slot != slot) || origin->definition.retired ||
            origin->definition.address != definition->address) continue;
        if (!direct && (!ReadCaptureMemory(reinterpret_cast<void*>(origin->slot), &target, sizeof(target)) ||
            target != definition->address)) continue;
        auto result = &origin->definition;
        dr_mutex_unlock(DefinitionLock);
        return result;
    }
    if (!direct && NonImportCallers[nonImportBucket].caller == caller)
    {
        dr_mutex_unlock(DefinitionLock);
        return definition;
    }
    dr_mutex_unlock(DefinitionLock);
    auto importer = dr_lookup_module(reinterpret_cast<app_pc>(caller - 1));
    if (!importer) return definition;
    if (!direct)
    {
        thunk = 0;
        slot = ImportRegisterSlot(*importer, caller);
        if (!slot)
        {
            dr_mutex_lock(DefinitionLock);
            if (ImportEpoch == epoch) NonImportCallers[nonImportBucket] = {caller, importer->start};
            dr_mutex_unlock(DefinitionLock);
            dr_free_module_data(importer);
            return definition;
        }
        if (!ReadCaptureMemory(reinterpret_cast<void*>(slot), &target, sizeof(target)) ||
            target != definition->address)
        {
            dr_free_module_data(importer);
            return definition;
        }
    }
    char library[256]{}, name[MaximumApiNameBytes]{};
    const RuntimeExport* runtime = nullptr;
    Api typed = Api::Count;
    app_pc provider = nullptr;
    auto valid = reinterpret_cast<uint64_t>(importer->start) <= caller - (thunk ? 5u : 6u) &&
        reinterpret_cast<uint64_t>(importer->end) >= caller &&
        (!thunk || thunk >= reinterpret_cast<uint64_t>(importer->start) &&
            thunk <= reinterpret_cast<uint64_t>(importer->end) - sizeof(instruction)) &&
        slot >= reinterpret_cast<uint64_t>(importer->start) &&
        slot <= reinterpret_cast<uint64_t>(importer->end) - sizeof(void*) &&
        ImportSlotContract(*importer, slot, target, library, std::size(library), name, std::size(name),
            runtime, typed, provider);
    if (!valid)
    {
        dr_free_module_data(importer);
        return definition;
    }
    dr_mutex_lock(DefinitionLock);
    if (ImportEpoch != epoch || definition->retired || ImportOriginCount >= MaxImportOrigins)
    {
        dr_mutex_unlock(DefinitionLock);
        dr_free_module_data(importer);
        return definition;
    }
    for (auto origin = ImportOrigins[bucket]; origin; origin = origin->next)
    {
        if (origin->caller != caller || origin->slot != slot || origin->definition.retired ||
            origin->definition.address != target) continue;
        auto result = &origin->definition;
        dr_mutex_unlock(DefinitionLock);
        dr_free_module_data(importer);
        return result;
    }
    auto origin = static_cast<ImportOrigin*>(dr_global_alloc(sizeof(ImportOrigin)));
    memset(origin, 0, sizeof(*origin));
    origin->caller = caller;
    origin->slot = slot;
    origin->importer = importer->start;
    origin->provider = provider;
    auto& bound = origin->definition;
    bound.typed = typed;
    bound.known = typed != Api::Count;
    bound.id = bound.known ? typed : static_cast<Api>(NextExportId++);
    bound.runtime = runtime;

    // The ANSI AVI hook resolves direct imports before recording its shared implementation.
    bound.nativeImportAlias = direct && typed == Api::AVISaveA;
    bound.signature = bound.known ? SignatureFor(typed) : runtime->signature;
    bound.interfaceInputs = bound.known ? PublicInterfaceInputs(typed) : 0;
    bound.address = target;
    bound.module = definition->module;
    bound.mask = bound.known ? ApiMask(typed) : definition->mask;
    bound.metadata.argumentCount = bound.known ? Definition(typed).argumentCount :
        runtime->CapturedArgumentCount();
    dr_snprintf(bound.metadata.module, std::size(bound.metadata.module), "%s", library);
    dr_snprintf(bound.metadata.name, std::size(bound.metadata.name), "%s", name);
    CopyDescription(bound.metadata.parameters, std::size(bound.metadata.parameters),
        bound.known ? Definition(typed).parameters : runtime->description);
    // Known imports can arrive through an API-set alias; use the catalog identity that TraceStore persists for their
    // ID.
    bound.metadata.category = bound.known ? ClassifyApi(Definition(typed).module, Definition(typed).name) :
        ClassifyApi(library, name);
    bound.categoryMask = CategoryMask(bound.metadata.category);
    bound.nameHash = ApiNameHash(name);
    bound.asyncRole = AsyncRole(library, name);
    origin->next = ImportOrigins[bucket];
    ImportOrigins[bucket] = origin;
    ++ImportOriginCount;
    dr_mutex_unlock(DefinitionLock);
    dr_free_module_data(importer);
    return &bound;
}

void ForgetInstructionImports(const module_data_t* module)
{
    // Retain immutable records until shutdown because an active invocation can still reference a retired image.
    dr_mutex_lock(DefinitionLock);
    ++ImportEpoch;
    for (auto bucket : ImportOrigins)
        for (auto origin = bucket; origin; origin = origin->next)
            if (origin->importer == module->start || origin->provider == module->start ||
                origin->definition.module == module->start)
                origin->definition.retired = true;
    for (auto& entry : NonImportCallers)
        if (entry.importer == module->start) entry = {};
    dr_mutex_unlock(DefinitionLock);
}

void FreeInstructionImports()
{
    for (auto& bucket : ImportOrigins)
    {
        while (bucket)
        {
            auto origin = bucket;
            bucket = origin->next;
            dr_global_free(origin, sizeof(*origin));
        }
    }
    memset(NonImportCallers, 0, sizeof(NonImportCallers));
    ImportOriginCount = 0;
}
}
