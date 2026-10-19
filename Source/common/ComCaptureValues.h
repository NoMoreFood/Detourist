#pragma once
#include "AutomationInterfaces.h"
#include <winstring.h>

namespace Detourist
{
constexpr uint32_t ComMaxEnumeratedItems = 16;

template<class T> bool ComValue(uint64_t address, T& value);

inline void CaptureComBstr(Slot* slot, SharedHeader* header, uint32_t parameter, BSTR text)
{
    uint32_t length = 0;
    auto address = reinterpret_cast<uint64_t>(text);
    if (address >= sizeof(length) && ComValue(address - sizeof(length), length))
        CopyValue(slot, header, parameter, ValueKind::Utf16, address, length);
}

inline void CaptureComVariantReference(Slot* slot, SharedHeader* header, uint32_t parameter, const VARIANT& value)
{
    if (value.vt == VT_BSTR || value.vt == (VT_BSTR | VT_BYREF))
    {
        BSTR text = value.bstrVal;
        if ((value.vt & VT_BYREF) && !ComValue(reinterpret_cast<uint64_t>(value.pbstrVal), text)) return;
        CaptureComBstr(slot, header, parameter, text);
    }
    else if (value.vt & VT_BYREF)
    {
        auto type = value.vt & VT_TYPEMASK;
        uint32_t size = type == VT_I1 || type == VT_UI1 ? 1 : type == VT_I2 || type == VT_UI2 ||
            type == VT_BOOL ? 2 : type == VT_I4 || type == VT_UI4 || type == VT_R4 || type == VT_ERROR ||
            type == VT_INT || type == VT_UINT ? 4 : type == VT_I8 || type == VT_UI8 || type == VT_R8 ||
            type == VT_CY || type == VT_DATE ? 8 : 0;
        if (size) CopyValue(slot, header, parameter, ValueKind::Scalar, reinterpret_cast<uint64_t>(value.byref), size);
    }
}

template<class State>
void CaptureComValues(State& call, Slot* slot, Api api, bool leaving, uint64_t queryIdentity)
{
    auto header = call.transport->Header();
    const auto& args = call.event.arguments;
    auto bytes = [&](uint32_t index, uint64_t length, ValueKind kind = ValueKind::Bytes)
    {
        CopyValue(slot, header, index, kind, args[index], length);
    };
    auto guid = [&](uint32_t index) { CaptureComGuid(call, slot, index, args[index]); };
    bool success = !(call.event.flags & Failed);
    if (!leaving)
    {
        switch (api)
        {
        case Api::CoCreateInstance: case Api::CoGetClassObject: guid(0); guid(3); break;
        case Api::CoCreateInstanceEx:
            guid(0);
            bytes(5, args[4] * sizeof(MULTI_QI));
            break;
        case Api::RoGetActivationFactory:
            guid(1);
            [[fallthrough]];
        case Api::RoActivateInstance:
            CaptureComString(call, slot, 0, reinterpret_cast<HSTRING>(args[0]));
            break;
        case Api::ComQueryInterface: CaptureComGuid(call, slot, 1, queryIdentity); break;
        case Api::ComCreateInstance: guid(2); break;
        case Api::ComGetIDsOfNames:
        {
            guid(1);
            bytes(2, args[3] * sizeof(void*));
            auto count = std::min<uint64_t>(args[3],
                std::min<uint32_t>(ComMaxEnumeratedItems, header->bufferLimit / sizeof(void*)));
            for (uint64_t index = 0; index < count; ++index)
            {
                wchar_t* name = nullptr;
                if (!ComValue(args[2] + index * sizeof(void*), name)) break;
                CopyValue(slot, header, 2, ValueKind::Utf16, reinterpret_cast<uint64_t>(name),
                    header->bufferLimit, {.terminated = true});
            }
            break;
        }
        case Api::ComInvoke: guid(2); break;
        default: break;
        }
    }
    else if (success)
    {
        switch (api)
        {
        case Api::CoCreateInstance: case Api::CoGetClassObject: bytes(4, sizeof(void*), ValueKind::Scalar); break;
        case Api::CoCreateInstanceEx: bytes(5, args[4] * sizeof(MULTI_QI)); break;
        case Api::RoGetActivationFactory: case Api::ComQueryInterface:
            bytes(2, sizeof(void*), ValueKind::Scalar); break;
        case Api::RoActivateInstance: case Api::ComActivateInstance:
            bytes(1, sizeof(void*), ValueKind::Scalar); break;
        case Api::ComCreateInstance: case Api::ComGetTypeInfo: bytes(3, sizeof(void*), ValueKind::Scalar); break;
        case Api::ComEnumVariantClone: bytes(1, sizeof(void*), ValueKind::Scalar); break;
        case Api::ComEnumVariantNext:
        {
            auto count = AutomationFetched(args[1], args[3], call.event.result);
            bytes(3, sizeof(ULONG), ValueKind::Scalar);
            auto offset = slot->event.payloadBytes;
            bytes(2, uint64_t{count} * sizeof(VARIANT));
            CaptureAutomationBuffer(slot, header, 2, args[2], offset);
            break;
        }
        case Api::ComGetTypeInfoCount: case Api::ComGetTrustLevel: bytes(1, sizeof(ULONG), ValueKind::Scalar); break;
        case Api::ComGetIDsOfNames: bytes(5, args[3] * sizeof(DISPID)); break;
        case Api::ComGetRuntimeClassName:
        {
            bytes(1, sizeof(HSTRING), ValueKind::Scalar);
            HSTRING name = nullptr;
            if (ComValue(args[1], name)) CaptureComString(call, slot, 1, name);
            break;
        }
        case Api::ComGetIids:
        {
            bytes(1, sizeof(ULONG), ValueKind::Scalar);
            bytes(2, sizeof(void*), ValueKind::Scalar);
            IID* identifiers = nullptr;
            auto count = SafeDword(args[1]);
            if (ComValue(args[2], identifiers))
                CopyValue(slot, header, 2, ValueKind::Bytes, reinterpret_cast<uint64_t>(identifiers),
                    uint64_t{count} * sizeof(IID));
            break;
        }
        default: break;
        }
    }

    // Dispatch arguments are reverse-ordered VARIANTs, with independently bounded nested string snapshots.
    if (api != Api::ComInvoke) return;
    DISPPARAMS parameters{};
    bytes(5, sizeof(DISPPARAMS));
    if (ComValue(args[5], parameters))
    {
        CopyValue(slot, header, 5, ValueKind::Bytes, reinterpret_cast<uint64_t>(parameters.rgdispidNamedArgs),
            uint64_t{parameters.cNamedArgs} * sizeof(DISPID));
        CopyValue(slot, header, 5, ValueKind::Bytes, reinterpret_cast<uint64_t>(parameters.rgvarg),
            uint64_t{parameters.cArgs} * sizeof(VARIANT));
        auto count = std::min<uint32_t>(parameters.cArgs,
            std::min<uint32_t>(ComMaxEnumeratedItems, (header->bufferLimit + sizeof(VARIANT) - 1) / sizeof(VARIANT)));
        for (uint32_t index = 0; index < count; ++index)
            CaptureComVariant(call, slot, 5, reinterpret_cast<uint64_t>(parameters.rgvarg + index));
    }
    if (!leaving) return;
    if (success) CaptureComVariant(call, slot, 6, args[6]);
    else if (static_cast<HRESULT>(call.event.result) == DISP_E_EXCEPTION)
    {
        bytes(7, sizeof(EXCEPINFO));
        EXCEPINFO exception{};
        if (ComValue(args[7], exception))
        {
            for (auto text : {exception.bstrSource, exception.bstrDescription, exception.bstrHelpFile})
                CaptureComBstr(slot, header, 7, text);
        }
    }
    else if (static_cast<HRESULT>(call.event.result) == DISP_E_TYPEMISMATCH ||
        static_cast<HRESULT>(call.event.result) == DISP_E_PARAMNOTFOUND) bytes(8, sizeof(UINT), ValueKind::Scalar);
}
}
