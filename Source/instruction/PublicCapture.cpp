#pragma warning(push)
#pragma warning(disable: 4995 4996)
#include "Win32Headers.inc"
#include "InstructionCapture.h"
#include "CaptureValues.h"

namespace Detourist
{
ExportSignature PublicSignature(Api api)
{
#define CORE_API(name, failure) ExportFunction<decltype(&::name)>::Signature(),
    static constexpr ExportSignature core[] =
    {
#include "CoreCatalog.inc"
    };
#undef CORE_API
#define WIN32_BINDING(name) ExportFunction<decltype(ResolveWin32Prototype(&::name))>::Signature(),
    static constexpr ExportSignature sdk[] =
    {
#include "Win32Bindings.h"
    };
#undef WIN32_BINDING
    auto index = static_cast<uint32_t>(api);
    if (index < NativeApiStart) return core[index];
    if (IsWin32Api(api)) return sdk[index - Win32ApiStart];
    return ComSignature(api);
}

uint32_t PublicInterfaceOutputs(Api api)
{
    // A public factory may return several independently typed COM interfaces.
#define WIN32_BINDING(name) ExportFunction<decltype(ResolveWin32Prototype(&::name))>::OutputInterfaces(),
    static constexpr uint32_t outputs[] =
    {
#include "Win32Bindings.h"
    };
#undef WIN32_BINDING
    return IsWin32Api(api) ? outputs[static_cast<uint32_t>(api) - Win32ApiStart] : 0;
}

const GUID* PublicInterfaceOutput(Api api, uint32_t parameter)
{
#define WIN32_BINDING(name) \
    case Api::name: return ExportFunction<decltype(ResolveWin32Prototype(&::name))>::OutputInterface(parameter);
    switch (api)
    {
#include "Win32Bindings.h"
    default: return nullptr;
    }
#undef WIN32_BINDING
}

uint32_t PublicInterfaceInputs(Api api)
{
#define WIN32_BINDING(name) ExportFunction<decltype(ResolveWin32Prototype(&::name))>::InputInterfaces(),
    static constexpr uint32_t inputs[] =
    {
#include "Win32Bindings.h"
    };
#undef WIN32_BINDING
    if (IsWin32Api(api)) return inputs[static_cast<uint32_t>(api) - Win32ApiStart];
    if (api == Api::CoCreateInstance) return ExportFunction<decltype(&::CoCreateInstance)>::InputInterfaces();
    if (api == Api::ComCreateInstance) return uint32_t{1} << 1;
    return 0;
}

const GUID* PublicInterfaceInput(Api api, uint32_t parameter)
{
#define WIN32_BINDING(name) \
    case Api::name: return ExportFunction<decltype(ResolveWin32Prototype(&::name))>::InputInterface(parameter);
    switch (api)
    {
#include "Win32Bindings.h"
    case Api::CoCreateInstance: return ExportFunction<decltype(&::CoCreateInstance)>::InputInterface(parameter);
    case Api::ComCreateInstance: return parameter == 1 ? &__uuidof(IUnknown) : nullptr;
    default: return nullptr;
    }
#undef WIN32_BINDING
}

void CapturePublicParameters(InstructionFrame& call, Slot* slot, bool leaving)
{
    auto header = call.transport->Header();
    const auto& args = call.event.arguments;
    auto bytes = [&](uint32_t index, uint64_t size, ValueKind kind = ValueKind::Bytes)
    {
        CopyValue(slot, header, index, kind, args[index], size);
    };
    auto text = [&](uint32_t index)
    {
        CopyValue(slot, header, index, ValueKind::Utf16, args[index], header->bufferLimit, {.terminated = true});
    };
    if (IsWin32Api(call.definition->typed))
    {
        CaptureBuiltinParameters(call, slot, leaving);
        return;
    }

    // Retain input capacities before the callee changes any in/out lengths.
    if (!leaving)
    {
        switch (call.definition->typed)
        {
        case Api::CreateFileW: text(0); bytes(3, sizeof(SECURITY_ATTRIBUTES)); break;
        case Api::DeleteFileW: case Api::RemoveDirectoryW: case Api::GetFileAttributesW:
        case Api::FindFirstFileExW: text(0); break;
        case Api::CreateDirectoryW: text(0); bytes(1, sizeof(SECURITY_ATTRIBUTES)); break;
        case Api::MoveFileExW: text(0); text(1); break;
        case Api::ReadFile: bytes(4, sizeof(OVERLAPPED)); break;
        case Api::WriteFile: bytes(1, args[2]); bytes(4, sizeof(OVERLAPPED)); break;
        case Api::RegOpenKeyExW: text(1); break;
        case Api::RegQueryValueExW: text(1); call.requestedBytes = SafeDword(args[5]); break;
        case Api::RegCreateKeyExW: text(1); text(3); bytes(6, sizeof(SECURITY_ATTRIBUTES)); break;
        case Api::RegSetValueExW: text(1); bytes(4, args[5]); break;
        case Api::CreateProcessW:
            text(0); text(1); text(7); bytes(2, sizeof(SECURITY_ATTRIBUTES));
            bytes(3, sizeof(SECURITY_ATTRIBUTES)); bytes(8, sizeof(STARTUPINFOW)); break;
        case Api::CoCreateInstance: bytes(0, sizeof(GUID)); bytes(3, sizeof(GUID)); break;
        case Api::CoCreateInstanceEx:
            bytes(0, sizeof(GUID)); bytes(3, sizeof(COSERVERINFO));
            bytes(5, Win32ByteCount(args[4], sizeof(MULTI_QI))); break;
        case Api::CoGetClassObject:
            bytes(0, sizeof(GUID)); bytes(2, sizeof(COSERVERINFO)); bytes(3, sizeof(GUID)); break;
        case Api::RoGetActivationFactory: bytes(1, sizeof(GUID)); break;
        default: break;
        }
        return;
    }

    CaptureCoreOutputs(call.definition->typed, call.event, call.requestedBytes, args[2], slot, header);
    bool success = !(call.event.flags & Failed);
    switch (call.definition->typed)
    {
    case Api::CoCreateInstance: case Api::CoGetClassObject:
        if (success) bytes(4, sizeof(void*), ValueKind::Scalar); break;
    case Api::CoCreateInstanceEx:
        if (success) bytes(5, Win32ByteCount(args[4], sizeof(MULTI_QI))); break;
    case Api::RoGetActivationFactory:
        if (success) bytes(2, sizeof(void*), ValueKind::Scalar); break;
    case Api::RoActivateInstance:
        if (success) bytes(1, sizeof(void*), ValueKind::Scalar); break;
    default: break;
    }
}
}
#pragma warning(pop)
