#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "InstructionCapture.h"
#include <algorithm>
#include <iterator>

namespace Detourist
{
constexpr uint32_t TlsSlotLimit = 1088;

struct LocaleInstruction
{
    int opcode = OP_INVALID;
    opnd_t sources[4]{}, destination{};
    uint32_t sourceCount = 0;
    app_pc next = nullptr, target = nullptr;
};

bool ReadLocaleInstruction(void* context, app_pc address, LocaleInstruction& result)
{
    byte code[MaxX86InstructionBytes]{};
    if (!ReadCaptureMemory(address, code, sizeof(code))) return false;
    instr_t instruction;
    instr_init(context, &instruction);
    const auto next = decode_from_copy(context, code, address, &instruction);
    const auto count = next ? instr_num_srcs(&instruction) : 0;
    const bool valid = next && next > code && next <= code + sizeof(code) &&
        count <= std::size(result.sources);
    if (valid)
    {
        result.opcode = instr_get_opcode(&instruction);
        result.sourceCount = count;
        for (uint32_t index = 0; index < result.sourceCount; ++index)
            result.sources[index] = instr_get_src(&instruction, index);
        result.destination = instr_num_dsts(&instruction) ? instr_get_dst(&instruction, 0) : opnd_create_null();
        result.next = address + (next - code);
        if (instr_is_call_direct(&instruction)) result.target = opnd_get_pc(instr_get_target(&instruction));
        else if (instr_is_call_indirect(&instruction) && count && InstructionStaticAddress(result.sources[0]))
            ReadCaptureMemory(opnd_get_addr(result.sources[0]), &result.target, sizeof(result.target));
    }
    instr_free(context, &instruction);
    return valid && result.opcode != OP_int3;
}

bool ReadLocaleThreadSlot(void* context, uint32_t index, bool fiber, void*& value)
{
    auto module = dr_lookup_module_by_name("ntdll.dll");
    const auto read = reinterpret_cast<NTSTATUS (NTAPI *)(ULONG, void**)>(
        module ? dr_get_proc_address(module->handle, "RtlFlsGetValue") : nullptr);
    if (module) dr_free_module_data(module);
    if (fiber && !read || !fiber && index >= TlsSlotLimit) return false;

    // The OS getter reads the application's FLS without initializing CRT state or acquiring its locks.
    dr_switch_to_app_state_ex(context, DR_STATE_TEB_MISC);
    bool valid = false;
    if (fiber)
    {
        const auto status = read(index, &value);
        valid = NT_SUCCESS(status) || status == STATUS_MEMORY_NOT_ALLOCATED;
    }
    else
    {
        auto teb = NtCurrentTeb();
        auto slot = index < TLS_MINIMUM_AVAILABLE ? teb->TlsSlots + index :
            teb->TlsExpansionSlots ? teb->TlsExpansionSlots + index - TLS_MINIMUM_AVAILABLE : nullptr;
        valid = !slot || ReadCaptureMemory(slot, &value, sizeof(value));
    }
    dr_switch_to_dr_state_ex(context, DR_STATE_TEB_MISC);
    return valid;
}

bool LocaleThreadAccessor(void* context, app_pc address, bool& fiber)
{
    constexpr const char* names[]{"FlsGetValue", "FlsGetValue2", "TlsGetValue", "TlsGetValue2"};
    app_pc expected[9]{};
    for (uint32_t provider = 0; provider < 2; ++provider)
    {
        auto module = dr_lookup_module_by_name(provider ? "kernel32.dll" : "kernelbase.dll");
        if (!module) continue;
        for (uint32_t index = 0; index < std::size(names); ++index)
            expected[provider * 4 + index] = reinterpret_cast<app_pc>(
                dr_get_proc_address(module->handle, names[index]));
        dr_free_module_data(module);
    }
    auto module = dr_lookup_module_by_name("ntdll.dll");
    if (module)
    {
        expected[8] = reinterpret_cast<app_pc>(dr_get_proc_address(module->handle, "RtlFlsGetValue2"));
        dr_free_module_data(module);
    }
    auto matches = [&](app_pc target)
    {
        for (uint32_t index = 0; index < std::size(expected); ++index)
            if (expected[index] && target == expected[index]) { fiber = index % 4 < 2; return true; }
        return false;
    };
    if (matches(address)) return true;

    // CRT wrappers can hold an encoded Windows getter or a direct imported fallback.
    uintptr_t target = 0;
    bool loaded = false;
    for (auto current = address; current < address + 48;)
    {
        LocaleInstruction operation;
        if (!ReadLocaleInstruction(context, current, operation)) return false;
        if ((operation.opcode == OP_mov_ld || operation.opcode == OP_xor) &&
            opnd_is_reg(operation.destination) && opnd_get_reg(operation.destination) == DR_REG_XAX)
        {
            for (uint32_t index = 0; index < operation.sourceCount; ++index)
            {
                const auto source = operation.sources[index];
                if (!InstructionStaticAddress(source)) continue;
                uintptr_t value = 0;
                if (!ReadCaptureMemory(opnd_get_addr(source), &value, sizeof(value))) return false;
                if (operation.opcode == OP_xor) target ^= value;
                else { target = value; loaded = true; }
            }
        }
        if (operation.opcode == OP_jmp_ind && loaded)
        {
            return matches(reinterpret_cast<app_pc>(target));
        }
        if (operation.opcode == OP_ret) break;
        current = operation.next;
    }
    return false;
}

bool FindLocaleThreadSlot(void* context, app_pc address, app_pc start, app_pc end,
    uint32_t& index, bool& fiber, uint32_t& stride, uint32_t depth = 0)
{
    if (depth == 6 || address < start || address >= end) return false;
    app_pc argument = nullptr, guarded = nullptr;
    app_pc children[8]{};
    uint32_t childCount = 0;
    bool found = false;
    for (auto current = address; current < std::min(end, address + 384);)
    {
        LocaleInstruction operation;
        if (!ReadLocaleInstruction(context, current, operation)) break;
        app_pc relative = nullptr;
        bool invalidIndex = false;
        for (uint32_t ordinal = 0; ordinal < operation.sourceCount; ++ordinal)
        {
            const auto source = operation.sources[ordinal];
            if (InstructionStaticAddress(source) && opnd_get_size(source) == OPSZ_4)
                relative = reinterpret_cast<app_pc>(opnd_get_addr(source));
            if (opnd_is_immed_int(source))
            {
                const auto immediate = opnd_get_immed_int(source);
                invalidIndex |= immediate == -1;
                if (operation.opcode == OP_imul && immediate >= 256 && immediate <= 4096)
                    stride = static_cast<uint32_t>(immediate);
            }
        }
        if (operation.opcode == OP_cmp && invalidIndex) guarded = relative ? relative : argument;
        if (operation.opcode == OP_mov_ld && opnd_is_reg(operation.destination) &&
            opnd_get_reg(operation.destination) == DR_REG_ECX && relative)
        {
            argument = relative;
            if (!found && guarded == argument && ReadCaptureMemory(argument, &index, sizeof(index)))
            {
                fiber = true;
                found = true;
            }
        }
        if (operation.target)
        {
            if (!found && argument && LocaleThreadAccessor(context, operation.target, fiber) &&
                ReadCaptureMemory(argument, &index, sizeof(index))) found = true;
            if (!found && childCount < std::size(children)) children[childCount++] = operation.target;
            argument = nullptr;
        }
        if (operation.opcode == OP_ret) break;
        current = operation.next;
    }
    if (found) return index != UINT32_MAX;
    for (uint32_t child = 0; child < childCount; ++child)
        if (FindLocaleThreadSlot(context, children[child], start, end, index, fiber, stride, depth + 1)) return true;
    return false;
}

bool FindLocaleState(void* context, app_pc address, app_pc start, app_pc end,
    app_pc& enabled, app_pc& index, bool& direct, uint32_t depth = 0)
{
    if (depth == 4 || address < start || address >= end) return false;
    uint64_t argument = UINT64_MAX;
    for (auto current = address; current < std::min(end, address + 192);)
    {
        LocaleInstruction operation;
        if (!ReadLocaleInstruction(context, current, operation)) break;
        for (uint32_t ordinal = 0; ordinal < operation.sourceCount; ++ordinal)
        {
            const auto source = operation.sources[ordinal];
            if (!enabled && InstructionStaticAddress(source) && opnd_get_size(source) == OPSZ_1)
                enabled = reinterpret_cast<app_pc>(opnd_get_addr(source));
            if (!index && operation.opcode == OP_mov_ld && opnd_is_reg(operation.destination) &&
                opnd_get_reg(operation.destination) == DR_REG_ECX && InstructionStaticAddress(source) &&
                opnd_get_size(source) == OPSZ_4) index = reinterpret_cast<app_pc>(opnd_get_addr(source));
            if (opnd_is_base_disp(source) && opnd_get_segment(source) == (sizeof(void*) == 8 ? DR_SEG_GS : DR_SEG_FS) &&
                opnd_get_base(source) == DR_REG_NULL && opnd_get_index(source) == DR_REG_NULL &&
                opnd_get_disp(source) == offsetof(TEB, ReservedForCrt) && opnd_get_size(source) == OPSZ_PTR)
                direct = true;
        }
        if (operation.target && argument == offsetof(TEB, ReservedForCrt))
        {
            LocaleInstruction store, load, segment, finish;
            if (ReadLocaleInstruction(context, operation.target, store) && store.opcode == OP_mov_st &&
                store.sourceCount == 1 && opnd_same(store.sources[0], opnd_create_reg(DR_REG_ECX)) &&
                opnd_is_base_disp(store.destination) && opnd_get_base(store.destination) == DR_REG_XSP &&
                opnd_get_index(store.destination) == DR_REG_NULL && ReadLocaleInstruction(context, store.next, load) &&
                load.opcode == OP_mov_ld && load.sourceCount == 1 && opnd_same(load.sources[0], store.destination) &&
                opnd_same(load.destination, opnd_create_reg(DR_REG_EAX)) &&
                ReadLocaleInstruction(context, load.next, segment) && segment.opcode == OP_mov_ld &&
                segment.sourceCount == 1 && opnd_same(segment.destination, opnd_create_reg(DR_REG_XAX)) &&
                opnd_is_base_disp(segment.sources[0]) &&
                opnd_get_segment(segment.sources[0]) == (sizeof(void*) == 8 ? DR_SEG_GS : DR_SEG_FS) &&
                opnd_get_base(segment.sources[0]) == DR_REG_XAX && opnd_get_index(segment.sources[0]) == DR_REG_NULL &&
                !opnd_get_disp(segment.sources[0]) && ReadLocaleInstruction(context, segment.next, finish) &&
                finish.opcode == OP_ret)
                direct = true;
        }
        if (operation.target)
            FindLocaleState(context, operation.target, start, end, enabled, index, direct, depth + 1);
        argument = operation.opcode == OP_mov_imm && operation.sourceCount == 1 &&
            opnd_same(operation.destination, opnd_create_reg(DR_REG_ECX)) &&
            opnd_is_immed_int(operation.sources[0]) ? opnd_get_immed_int(operation.sources[0]) : UINT64_MAX;
        if (operation.opcode == OP_ret && (!enabled || !direct)) break;
        current = operation.next;
    }
    return enabled && index && direct;
}

bool CurrentFormatLocale(InstructionFrame& call, bool ucrt, void*& information, bool completed)
{
    const auto module = reinterpret_cast<module_handle_t>(call.definition->module);
    auto accessor = reinterpret_cast<app_pc>(dr_get_proc_address(module, "__pctype_func"));
    auto image = dr_lookup_module(reinterpret_cast<app_pc>(module));
    if (!accessor || !image) { if (image) dr_free_module_data(image); return false; }
    const auto start = image->start, end = image->end;
    dr_free_module_data(image);
    auto context = dr_get_current_drcontext();
    app_pc getter = nullptr, state = nullptr, global = nullptr, mask = nullptr;
    int localeOffset = -1, flagsOffset = -1;
    const bool system = !_stricmp(call.definition->metadata.module, "msvcrt.dll");
    for (auto current = accessor; current < std::min(end, accessor + 160);)
    {
        LocaleInstruction operation;
        if (!ReadLocaleInstruction(context, current, operation)) break;
        if (operation.target)
        {
            if (!getter) getter = operation.target;
            else if (!global && !state) state = operation.target;
        }
        for (uint32_t ordinal = 0; ordinal < operation.sourceCount; ++ordinal)
        {
            const auto source = operation.sources[ordinal];
            if (InstructionStaticAddress(source))
            {
                if (operation.opcode == OP_cmp && opnd_get_size(source) == OPSZ_PTR ||
                    operation.opcode == OP_lea) global = reinterpret_cast<app_pc>(opnd_get_addr(source));
                if (operation.opcode == OP_test) mask = reinterpret_cast<app_pc>(opnd_get_addr(source));
            }
            if (!opnd_is_base_disp(source) || opnd_get_index(source) != DR_REG_NULL ||
                opnd_get_segment(source) != DR_REG_NULL) continue;
            const auto base = opnd_get_base(source);
            const auto size = opnd_get_size(source);
            const auto displacement = opnd_get_disp(source);
            if (getter && localeOffset < 0 && operation.opcode == OP_mov_ld && base == DR_REG_XAX &&
                size == OPSZ_PTR && displacement > 0 && displacement <= 512) localeOffset = displacement;
            if (global && (base == DR_REG_XAX || base == DR_REG_XCX || base == DR_REG_XDI) &&
                (size == OPSZ_4 || system && size == OPSZ_1) && displacement > localeOffset &&
                displacement <= 2048) flagsOffset = displacement;
        }
        current = operation.next;
    }

    // Unoptimized CRTs keep locale synchronization and state-array selection in separate helpers.
    if (ucrt && getter && !global && state)
    {
        app_pc value = nullptr, synchronize = nullptr;
        for (auto current = state; current < std::min(end, state + 128);)
        {
            LocaleInstruction operation;
            if (!ReadLocaleInstruction(context, current, operation)) break;
            if (operation.opcode == OP_lea && operation.sourceCount &&
                InstructionStaticAddress(operation.sources[0]))
                global = reinterpret_cast<app_pc>(opnd_get_addr(operation.sources[0]));
            if (operation.target)
            {
                if (!value) value = operation.target;
                else if (!synchronize) synchronize = operation.target;
            }
            if (operation.opcode == OP_ret) break;
            current = operation.next;
        }
        state = nullptr;
        if (value)
        {
            for (auto current = value; current < std::min(end, value + 64);)
            {
                LocaleInstruction operation;
                if (!ReadLocaleInstruction(context, current, operation)) break;
                if (operation.target) { state = operation.target; break; }
                if (operation.opcode == OP_ret) break;
                current = operation.next;
            }
        }
        if (synchronize)
        {
            for (auto current = synchronize; current < std::min(end, synchronize + 96);)
            {
                LocaleInstruction operation;
                if (!ReadLocaleInstruction(context, current, operation)) break;
                for (uint32_t ordinal = 0; ordinal < operation.sourceCount; ++ordinal)
                {
                    const auto source = operation.sources[ordinal];
                    if (operation.opcode != OP_mov_ld || opnd_get_size(source) != OPSZ_4) continue;
                    if (InstructionStaticAddress(source)) mask = reinterpret_cast<app_pc>(opnd_get_addr(source));
                    if (opnd_is_base_disp(source) && opnd_get_base(source) == DR_REG_XAX &&
                        opnd_get_index(source) == DR_REG_NULL && opnd_get_disp(source) > localeOffset &&
                        opnd_get_disp(source) <= 2048) flagsOffset = opnd_get_disp(source);
                }
                if (operation.opcode == OP_ret) break;
                current = operation.next;
            }
        }
    }
    if (!getter || localeOffset < 0 || flagsOffset < 0 || !global || !mask) return false;
    uint32_t index = 0, stride = 0;
    bool fiber = false;
    if (!FindLocaleThreadSlot(context, getter, start, end, index, fiber, stride)) return false;
    void* thread = nullptr;
    if (!ReadLocaleThreadSlot(context, index, fiber, thread)) return false;

    // Isolated UCRT state selects both the global locale and the matching element in its thread-data array.
    uint64_t stateIndex = 0;
    if (ucrt && state)
    {
        app_pc enabled = nullptr, stateSlot = nullptr;
        bool direct = false;
        uint8_t flag = 0;
        if (!FindLocaleState(context, state, start, end, enabled, stateSlot, direct) ||
            !ReadCaptureMemory(enabled, &flag, sizeof(flag)) ||
            !ReadCaptureMemory(stateSlot, &index, sizeof(index))) return false;
        dr_switch_to_app_state_ex(context, DR_STATE_TEB_MISC);
        const bool useTeb = flag && !NtCurrentTeb()->HasFiberData;
        if (useTeb) stateIndex = NtCurrentTeb()->ReservedForCrt;
        dr_switch_to_dr_state_ex(context, DR_STATE_TEB_MISC);
        if (!useTeb)
        {
            void* value = nullptr;
            if (!ReadLocaleThreadSlot(context, index, true, value)) return false;
            stateIndex = reinterpret_cast<uint64_t>(value);
        }
        if (stateIndex > 1 || stateIndex && !stride) return false;
    }
    auto data = thread ? static_cast<byte*>(thread) + stateIndex * stride : nullptr;

    // Completed scans retain the locale used by their conversions even if another thread changes the global locale.
    if (completed && thread) return ReadCaptureMemory(data + localeOffset, &information, sizeof(information));
    if (!ReadCaptureMemory(global + stateIndex * sizeof(void*), &information, sizeof(information))) return false;
    if (!thread) return information != nullptr;
    uint32_t flags = 0, globalMask = 0;
    if (!ReadCaptureMemory(data + flagsOffset, &flags, system ? 1 : sizeof(flags)) ||
        !ReadCaptureMemory(mask, &globalMask, system ? 1 : sizeof(globalMask))) return false;
    const bool own = system ? (flags & 2) || !(globalMask & 1) : (flags & globalMask) != 0;
    return !own || ReadCaptureMemory(data + localeOffset, &information, sizeof(information));
}
}
