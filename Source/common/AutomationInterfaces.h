#pragma once
#include "CaptureValues.h"
#include <oaidl.h>
#include <propidlbase.h>
#include <algorithm>
#include <array>

namespace Detourist
{
constexpr size_t AutomationMaxDepth = 32;
constexpr uint32_t VariantHeaderBytes = 16;
constexpr size_t AutomationInterfaceBatch = 128;

inline uint32_t AutomationFetched(uint64_t requested, uint64_t fetched, uint64_t result)
{
    // Failed outputs and unused capacity never establish returned values.
    if (static_cast<HRESULT>(result) < 0) return 0;
    uint32_t count = 0;
    if (fetched)
    {
        if (!ReadCaptureMemory(reinterpret_cast<void*>(fetched), &count, sizeof(count))) return 0;
    }
    else if (static_cast<ULONG>(requested) == 1 && static_cast<HRESULT>(result) == S_OK) count = 1;
    return std::min<uint32_t>(count, static_cast<ULONG>(requested));
}

inline void CaptureAutomationArrays(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    uint32_t stringFlags = 0, bool directArray = false, bool property = false)
{
    std::array<uint64_t, AutomationMaxDepth> path{};
    uint32_t nextArray = 0;

    // Array identities remain unique across property vectors and Automation arrays in one parameter.
    for (uint32_t offset = 0; offset + sizeof(Value) <= slot->event.payloadBytes;)
    {
        Value existing{};
        memcpy(&existing, Transport::Payload(slot) + offset, sizeof(existing));
        if ((existing.kind == ValueKind::SafeArray || existing.kind == ValueKind::PropertyVector) &&
            (existing.parameter & ValueParameterMask) == (parameter & ValueParameterMask))
            nextArray = std::max(nextArray, (existing.parameter >> ValueSubIndexShift) + 1);
        offset += static_cast<uint32_t>(sizeof(existing)) + existing.capturedBytes;
    }
    auto walk = [&](auto&& self, uint64_t pointer, size_t depth, uint32_t flags, bool propertyValue,
        uint32_t owner, uint32_t element, uint32_t available) -> void
    {
        if (!pointer || depth == path.size() || available < VariantHeaderBytes ||
            SlotMaxRemaining(slot, header) < sizeof(Value)) return;
        for (size_t index = 0; index < depth; ++index)
            if (path[index] == pointer) return;
        path[depth] = pointer;
        VARIANT value{};
        if (directArray && !depth)
        {
            value.vt = VT_ARRAY;
            value.parray = reinterpret_cast<SAFEARRAY*>(pointer);
        }
        else if (!ReadCaptureMemory(reinterpret_cast<void*>(pointer), &value,
            std::min<size_t>(available, sizeof(value))) ||
            value.vt & ~(VT_TYPEMASK | VT_BYREF | VT_ARRAY | (propertyValue ? VT_VECTOR : 0))) return;
        if (value.vt == (VT_VARIANT | VT_BYREF))
        {
            self(self, reinterpret_cast<uint64_t>(value.pvarVal), depth + 1, flags, propertyValue,
                owner, element, sizeof(VARIANT));
            return;
        }
        if (propertyValue && ((value.vt & VT_VECTOR) || value.vt == VT_BLOB || value.vt == VT_BLOB_OBJECT) &&
            available < sizeof(PROPVARIANT)) return;
        auto reference = owner == UINT32_MAX ? parameter :
            (parameter & ValueParameterMask) | (owner << ValueSubIndexShift);
        auto link = [&](uint32_t child)
        {
            if ((owner == UINT32_MAX && !(flags & StringArrayElement)) ||
                header->bufferLimit < sizeof(AutomationLink) ||
                SlotMaxRemaining(slot, header) < sizeof(Value) + sizeof(AutomationLink)) return;
            AutomationLink relation{owner, element, child, value.vt};
            CopyValue(slot, header, parameter, ValueKind::AutomationLink,
                reinterpret_cast<uint64_t>(&relation), sizeof(relation));
        };
        auto copy = [&](ValueKind kind, uint64_t source, uint64_t bytes, uint32_t attributes,
            bool readable = true, bool terminated = false) -> uint32_t
        {
            auto offset = slot->event.payloadBytes;
            CopyValue(slot, header, reference, kind, source && readable ? source : pointer,
                readable ? bytes : 0, {.terminated = terminated && source && readable});
            if (slot->event.payloadBytes == offset) return 0;
            Value captured{};
            memcpy(&captured, Transport::Payload(slot) + offset, sizeof(captured));
            captured.flags |= attributes | (readable ? 0u : Unreadable);
            if (!readable) captured.originalBytes = bytes;
            memcpy(Transport::Payload(slot) + offset, &captured, sizeof(captured));
            return captured.capturedBytes;
        };

        // Scalar references retain their resolved type and enclosing element, including by-reference variants.
        if (flags && (value.vt == VT_BSTR || value.vt == (VT_BSTR | VT_BYREF) ||
            propertyValue && (value.vt == VT_LPSTR || value.vt == VT_LPWSTR)))
        {
            auto counted = (value.vt & VT_TYPEMASK) == VT_BSTR;
            BSTR string = value.bstrVal;
            bool readable = !(value.vt & VT_BYREF) || ReadCaptureMemory(value.pbstrVal, &string, sizeof(string));
            auto source = reinterpret_cast<uint64_t>(string);
            if (!source && !counted && owner == UINT32_MAX) return;
            uint32_t bytes = source ? UINT32_MAX : 0;
            if (counted)
            {
                bytes = 0;
                readable = readable && (!source || source >= sizeof(bytes) &&
                    ReadCaptureMemory(reinterpret_cast<void*>(source - sizeof(bytes)), &bytes, sizeof(bytes)));
            }
            link(UINT32_MAX);
            copy(value.vt == VT_LPSTR ? ValueKind::Bytes : ValueKind::Utf16,
                source, bytes, flags, readable, !counted);
            return;
        }
        if (flags && propertyValue && (value.vt == VT_BLOB || value.vt == VT_BLOB_OBJECT || value.vt == VT_CLSID))
        {
            PROPVARIANT scalar{};
            memcpy(&scalar, &value, sizeof(scalar));
            auto guid = value.vt == VT_CLSID;
            auto source = reinterpret_cast<uint64_t>(guid ? static_cast<void*>(scalar.puuid) : scalar.blob.pBlobData);
            auto bytes = guid ? sizeof(GUID) : uint64_t{scalar.blob.cbSize};
            link(UINT32_MAX);
            copy(ValueKind::Bytes, source, bytes, flags, (!bytes || source) && source <= UINT64_MAX - bytes);
            return;
        }
        if (flags && propertyValue && value.vt == VT_CF)
        {
            // Clipboard size includes the format field but excludes the CLIPDATA header and pointer.
            auto source = reinterpret_cast<uint64_t>(value.byref);
            if (!source) return;
            link(UINT32_MAX);
            auto offset = slot->event.payloadBytes;
            if (copy(ValueKind::PropertyClipboard, source, sizeof(CLIPDATA), flags) < sizeof(CLIPDATA)) return;
            CLIPDATA clipboard{};
            memcpy(&clipboard, Transport::Payload(slot) + offset + sizeof(Value), sizeof(clipboard));
            auto data = reinterpret_cast<uint64_t>(clipboard.pClipData);
            auto bytes = clipboard.cbSize >= sizeof(clipboard.ulClipFmt) ? CBPCLIPDATA(clipboard) : 0;
            copy(ValueKind::Bytes, data, bytes, flags, clipboard.cbSize >= sizeof(clipboard.ulClipFmt) &&
                (!bytes || data) && data <= UINT64_MAX - bytes);
            return;
        }
        if (flags && (value.vt & ~VT_TYPEMASK) == VT_BYREF)
        {
            uint32_t bytes = 0;
            switch (value.vt & VT_TYPEMASK)
            {
            case VT_I1: case VT_UI1: bytes = 1; break;
            case VT_I2: case VT_UI2: case VT_BOOL: bytes = 2; break;
            case VT_I4: case VT_UI4: case VT_INT: case VT_UINT: case VT_R4: case VT_ERROR: bytes = 4; break;
            case VT_I8: case VT_UI8: case VT_R8: case VT_DATE: case VT_CY: bytes = 8; break;
            case VT_DECIMAL: bytes = sizeof(DECIMAL); break;
            default: return;
            }
            auto source = reinterpret_cast<uint64_t>(value.byref);
            link(UINT32_MAX);
            copy(bytes <= 8 ? ValueKind::Scalar : ValueKind::Bytes, source, bytes, flags,
                source && source <= UINT64_MAX - bytes);
            return;
        }

        // Property vectors and SAFEARRAYs share bounded traversal while retaining their distinct layouts.
        auto vector = propertyValue && (value.vt & VT_VECTOR);
        auto type = value.vt & VT_TYPEMASK;
        uint32_t width = 0;
        uint64_t count = 0, data = 0, descriptorAddress = 0, descriptorBytes = 0;
        bool readable = true;
        if (vector)
        {
            if (value.vt & (VT_BYREF | VT_ARRAY | VT_RESERVED)) return;
            switch (type)
            {
            case VT_I1: case VT_UI1: width = 1; break;
            case VT_I2: case VT_UI2: case VT_BOOL: width = 2; break;
            case VT_I4: case VT_UI4: case VT_INT: case VT_UINT: case VT_R4: case VT_ERROR: width = 4; break;
            case VT_I8: case VT_UI8: case VT_R8: case VT_DATE: case VT_CY: case VT_FILETIME:
            case VT_BSTR: case VT_LPSTR: case VT_LPWSTR: width = 8; break;
            case VT_CLSID: width = sizeof(GUID); break;
            case VT_CF: width = sizeof(CLIPDATA); break;
            case VT_VARIANT: width = sizeof(PROPVARIANT); break;
            default: return;
            }
            PROPVARIANT propertyVector{};
            memcpy(&propertyVector, &value, sizeof(propertyVector));
            descriptorAddress = pointer + offsetof(PROPVARIANT, capropvar);
            descriptorBytes = sizeof(CAPROPVARIANT);
            count = propertyVector.capropvar.cElems;
            data = reinterpret_cast<uint64_t>(propertyVector.capropvar.pElems);
        }
        else
        {
            if (!(value.vt & VT_ARRAY)) return;
            SAFEARRAY* array = value.parray;
            if (value.vt & VT_BYREF)
                if (!ReadCaptureMemory(value.pparray, &array, sizeof(array))) return;
            SAFEARRAY descriptor{};
            constexpr auto bounds = offsetof(SAFEARRAY, rgsabound);
            if (!array) return;
            if (!ReadCaptureMemory(array, &descriptor, bounds) || !descriptor.cDims)
            {
                if (directArray && !depth)
                    CopyValue(slot, header, parameter, ValueKind::SafeArray, pointer, bounds);
                return;
            }
            if (directArray && !depth)
            {
                switch (descriptor.fFeatures & (FADF_BSTR | FADF_UNKNOWN | FADF_DISPATCH | FADF_VARIANT | FADF_RECORD))
                {
                case FADF_BSTR: type = VT_BSTR; break;
                case FADF_UNKNOWN: type = VT_UNKNOWN; break;
                case FADF_DISPATCH: type = VT_DISPATCH; break;
                case FADF_VARIANT: type = VT_VARIANT; break;
                case FADF_RECORD: type = VT_RECORD; break;
                }
            }
            descriptorAddress = reinterpret_cast<uint64_t>(array);
            descriptorBytes = bounds + uint64_t{descriptor.cDims} * sizeof(SAFEARRAYBOUND);
            width = descriptor.cbElements;
            data = reinterpret_cast<uint64_t>(descriptor.pvData);
            count = 1;
            for (uint32_t dimension = 0; dimension < descriptor.cDims; ++dimension)
            {
                SAFEARRAYBOUND extent{};
                auto offset = bounds + uint64_t{dimension} * sizeof(extent);
                if (descriptorAddress > UINT64_MAX - offset ||
                    !ReadCaptureMemory(reinterpret_cast<void*>(descriptorAddress + offset), &extent, sizeof(extent)) ||
                    extent.cElements && count > UINT64_MAX / extent.cElements)
                {
                    readable = false;
                    break;
                }
                count *= extent.cElements;
            }
        }
        auto arrayIndex = nextArray++;
        link(arrayIndex);
        reference = (parameter & ValueParameterMask) | (arrayIndex << ValueSubIndexShift);
        auto attributes = static_cast<uint32_t>(type) << ValueDetailShift;
        copy(vector ? ValueKind::PropertyVector : ValueKind::SafeArray, descriptorAddress, descriptorBytes, attributes);
        auto bytes = width && count <= UINT64_MAX / width ? count * width : 0;
        readable = readable && width && count <= UINT64_MAX / width && (!count || data) && data <= UINT64_MAX - bytes;
        auto dataOffset = slot->event.payloadBytes;
        auto captured = copy(vector ? ValueKind::PropertyVectorData : ValueKind::SafeArrayData,
            data, bytes, attributes, readable);
        if (!captured) return;

        // Follow only complete reference fields retained in the recorded elements, with one bound per pointee.
        if (vector && type == VT_CF)
        {
            for (uint32_t index = 0; index <= UINT16_MAX && uint64_t{index + 1} * width <= captured; ++index)
            {
                VARIANT clipboard{};
                clipboard.vt = VT_CF;
                clipboard.byref = reinterpret_cast<void*>(data + uint64_t{index} * width);
                self(self, reinterpret_cast<uint64_t>(&clipboard), depth + 1,
                    AutomationElement | ReferencedData | (index << ValueDetailShift), true, arrayIndex, index,
                    sizeof(clipboard));
            }
            return;
        }
        if ((type == VT_BSTR || vector && (type == VT_LPSTR || type == VT_LPWSTR)) && width == sizeof(void*))
        {
            auto visible = std::min<uint32_t>(captured / width, UINT16_MAX + 1u);
            for (uint32_t index = 0; index < visible; ++index)
            {
                VARIANT string{};
                string.vt = static_cast<VARTYPE>(type);
                memcpy(&string.byref, Transport::Payload(slot) + dataOffset + sizeof(Value) +
                    uint64_t{index} * width, sizeof(void*));
                self(self, reinterpret_cast<uint64_t>(&string), depth + 1,
                    AutomationElement | ReferencedData | (index << ValueDetailShift), vector, arrayIndex, index,
                    sizeof(string));
            }
            return;
        }
        if (type != VT_VARIANT || width != sizeof(VARIANT)) return;
        for (uint32_t index = 0; index <= UINT16_MAX && uint64_t{index} * width + VariantHeaderBytes <= captured;
            ++index)
            self(self, data + uint64_t{index} * width, depth + 1,
                AutomationElement | ReferencedData | (index << ValueDetailShift), vector, arrayIndex, index,
                std::min(width, captured - index * width));
    };
    walk(walk, address, 0, stringFlags, property, UINT32_MAX, stringFlags >> ValueDetailShift, sizeof(VARIANT));
}

inline void CaptureAutomationBuffer(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, uint32_t snapshotOffset, bool scalar = false, bool property = false)
{
    if (slot->event.payloadBytes < snapshotOffset + sizeof(Value)) return;
    Value captured{};
    memcpy(&captured, Transport::Payload(slot) + snapshotOffset, sizeof(captured));

    // Follow only variant headers whose tag and pointer are present in the bounded buffer snapshot.
    auto count = std::min<uint64_t>(captured.originalBytes / sizeof(VARIANT), UINT16_MAX + 1u);
    for (uint32_t index = 0; index < count &&
        uint64_t{index} * sizeof(VARIANT) + VariantHeaderBytes <= captured.capturedBytes &&
        SlotMaxRemaining(slot, header) >= sizeof(Value); ++index)
    {
        auto offset = uint64_t{index} * sizeof(VARIANT);
        if (address > UINT64_MAX - offset) break;
        VARTYPE type = VT_EMPTY;
        memcpy(&type, Transport::Payload(slot) + snapshotOffset + sizeof(Value) + offset, sizeof(type));
        if (property && (type == VT_BLOB || type == VT_BLOB_OBJECT || !scalar && (type & VT_VECTOR)) &&
            offset + sizeof(PROPVARIANT) > captured.capturedBytes) continue;
        CaptureAutomationArrays(slot, header, parameter, address + offset,
            ReferencedData | (scalar ? 0u : StringArrayElement | (index << ValueDetailShift)), false, property);
    }
}

template<class Visit> bool ForEachAutomationInterface(uint64_t address, Visit&& visit, bool property = false)
{
    // Report element readability separately from unavailable pointees so traversal can retain later siblings.
    static_assert(sizeof(PROPVARIANT) == sizeof(VARIANT) &&
        offsetof(PROPVARIANT, punkVal) == offsetof(VARIANT, punkVal));
    std::array<uint64_t, AutomationMaxDepth> path{};
    auto walk = [&](auto&& self, uint64_t pointer, size_t depth, bool propertyValue) -> bool
    {
        if (!pointer) return false;
        if (depth == path.size()) return true;
        for (size_t index = 0; index < depth; ++index)
            if (path[index] == pointer) return true;
        path[depth] = pointer;
        VARIANT value{};
        if (!ReadCaptureMemory(reinterpret_cast<void*>(pointer), &value, sizeof(value))) return false;
        if (value.vt & ~(VT_TYPEMASK | VT_BYREF | VT_ARRAY | (propertyValue ? VT_VECTOR : 0))) return true;
        auto type = value.vt & VT_TYPEMASK;
        if (propertyValue && type == VT_RECORD) return true;
        if (propertyValue && (value.vt & VT_VECTOR))
        {
            if (value.vt != (VT_VECTOR | VT_VARIANT) || depth + 1 == path.size()) return true;
            PROPVARIANT vector{};
            memcpy(&vector, &value, sizeof(vector));
            auto data = reinterpret_cast<uint64_t>(vector.capropvar.pElems);
            auto count = uint64_t{vector.capropvar.cElems};
            if (!data || data > UINT64_MAX - count * sizeof(PROPVARIANT)) return true;

            // Property vectors contain property variants and stop at the first unreadable element.
            for (uint64_t index = 0; index < count; ++index)
            {
                auto child = data + index * sizeof(PROPVARIANT);
                if (!self(self, child, depth + 1, true)) break;
            }
            return true;
        }
        if (propertyValue && value.vt == type)
        {
            if (type == VT_STREAM || type == VT_STREAMED_OBJECT || type == VT_STORAGE || type == VT_STORED_OBJECT)
            {
                if (value.punkVal) visit(value.punkVal, type == VT_STREAM || type == VT_STREAMED_OBJECT ?
                    __uuidof(IStream) : __uuidof(IStorage));
                return true;
            }
            if (type == VT_VERSIONED_STREAM)
            {
                VERSIONEDSTREAM stream{};
                if (value.byref && ReadCaptureMemory(value.byref, &stream, sizeof(stream)) && stream.pStream)
                    visit(stream.pStream, __uuidof(IStream));
                return true;
            }
        }
        if (type == VT_VARIANT && (value.vt & VT_BYREF) && !(value.vt & VT_ARRAY))
        {
            self(self, reinterpret_cast<uint64_t>(value.pvarVal), depth + 1, propertyValue);
            return true;
        }
        if (!(value.vt & VT_ARRAY))
        {
            // Records carry their descriptive interface directly, including records passed by reference.
            if (type == VT_RECORD)
            {
                if (value.pRecInfo) visit(value.pRecInfo, __uuidof(IRecordInfo));
                return true;
            }
            if (type != VT_DISPATCH && type != VT_UNKNOWN) return true;
            void* instance = value.punkVal;
            if (value.vt & VT_BYREF)
                if (!ReadCaptureMemory(value.byref, &instance, sizeof(instance))) return true;
            if (instance) visit(instance, type == VT_DISPATCH ? __uuidof(IDispatch) : __uuidof(IUnknown));
            return true;
        }
        if (type != VT_DISPATCH && type != VT_UNKNOWN && type != VT_VARIANT && type != VT_RECORD) return true;
        SAFEARRAY* array = value.parray;
        if (value.vt & VT_BYREF)
            if (!ReadCaptureMemory(value.pparray, &array, sizeof(array))) return true;
        SAFEARRAY header{};
        constexpr auto bounds = offsetof(SAFEARRAY, rgsabound);
        if (!array || !ReadCaptureMemory(array, &header, bounds) || !header.cDims || !header.cbElements) return true;
        auto descriptor = reinterpret_cast<uint64_t>(array);

        // Record arrays expose their provider in the descriptor prefix without querying the target object.
        if (type == VT_RECORD)
        {
            IRecordInfo* info = nullptr;
            if ((header.fFeatures & FADF_RECORD) && descriptor >= sizeof(info) &&
                ReadCaptureMemory(reinterpret_cast<void*>(descriptor - sizeof(info)), &info, sizeof(info)) && info)
                visit(info, __uuidof(IRecordInfo));
            return true;
        }
        if (!header.pvData || header.cbElements != (type == VT_VARIANT ? sizeof(VARIANT) : sizeof(void*))) return true;

        // Flatten the declared dimensions, retaining lower-bound independence and checked byte extents.
        uint64_t count = 1;
        for (uint32_t dimension = 0; dimension < header.cDims; ++dimension)
        {
            SAFEARRAYBOUND extent{};
            auto offset = bounds + uint64_t{dimension} * sizeof(extent);
            if (descriptor > UINT64_MAX - offset ||
                !ReadCaptureMemory(reinterpret_cast<void*>(descriptor + offset), &extent, sizeof(extent)) ||
                extent.cElements && count > UINT64_MAX / extent.cElements) return true;
            count *= extent.cElements;
        }
        auto data = reinterpret_cast<uint64_t>(header.pvData);
        if (!count || count > UINT64_MAX / header.cbElements || data > UINT64_MAX - count * header.cbElements)
            return true;

        // Nested values have bounded recursion; interface arrays use a fixed temporary block and add no references.
        if (type == VT_VARIANT)
        {
            if (depth + 1 == path.size()) return true;
            for (uint64_t index = 0; index < count; ++index)
                if (!self(self, data + index * sizeof(VARIANT), depth + 1, false)) break;
            return true;
        }
        void* instances[AutomationInterfaceBatch];
        for (uint64_t offset = 0; offset < count;)
        {
            auto batch = std::min<uint64_t>(count - offset, std::size(instances));
            if (!ReadCaptureMemory(reinterpret_cast<void*>(data + offset * sizeof(void*)),
                instances, static_cast<size_t>(batch) * sizeof(void*))) return true;
            for (uint64_t index = 0; index < batch; ++index)
                if (instances[index]) visit(instances[index],
                    type == VT_DISPATCH ? __uuidof(IDispatch) : __uuidof(IUnknown));
            offset += batch;
        }
        return true;
    };
    return walk(walk, address, 0, property);
}

template<class Visit> void ForEachAutomationElement(uint64_t address, uint64_t count, Visit&& visit,
    bool property = false)
{
    // Completed values establish interfaces independently of the captured byte limit.
    // Unreadable contiguous storage ends traversal; unavailable pointees do not hide readable siblings.
    if (!address || count > UINT64_MAX / sizeof(VARIANT)) return;
    auto bytes = count * sizeof(VARIANT);
    if (address > UINT64_MAX - bytes) return;
    for (uint64_t index = 0; index < count; ++index)
        if (!ForEachAutomationInterface(address + index * sizeof(VARIANT), visit, property)) break;
}

template<class Visit> void ForEachAutomationInput(uint64_t address, Visit&& visit)
{
    DISPPARAMS parameters{};
    if (!address || !ReadCaptureMemory(reinterpret_cast<void*>(address), &parameters, sizeof(parameters))) return;
    ForEachAutomationElement(reinterpret_cast<uint64_t>(parameters.rgvarg), parameters.cArgs, visit);
}
}
