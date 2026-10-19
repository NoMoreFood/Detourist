#pragma once
#include "CatalogView.h"
#include "CaptureValues.h"
#include "AutomationInterfaces.h"
#include "LdapCaptureValues.h"
#include "AuthzCaptureValues.h"
#include "PrintDocumentCapture.h"
#include "AuthzOperationsCapture.h"
#include "EapErrorCapture.h"
#include "RtmCaptureValues.h"
#include <algorithm>
#include <array>
#include <span>

namespace Detourist
{
void CaptureStringPairs(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    uint64_t bytes, bool wide, bool guarded = false);
void CaptureAviStreams(const Event& event, Slot* slot, SharedHeader* header);
uint64_t MapiAddressBytes(uint32_t count);
void CaptureMapiProperties(Slot* slot, SharedHeader* header, uint32_t parameter, uint32_t snapshot);
void CaptureMapiAddressList(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    uint64_t capacity);
void CaptureX509Certificate(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    bool indirect = false);
void CaptureEtwDescriptors(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, uint32_t count, uint32_t format = 0);
void CaptureClassicEtwEvent(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, uint32_t headerBytes);
void CaptureNetApiRecords(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t output, uint64_t countPointer, uint32_t family, uint32_t level, bool singleRecord = false);
void CaptureReplicationInformation(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, uint32_t selector);
void CaptureSyncAllErrors(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address, bool wide);
void CaptureSamReferences(Slot* slot, SharedHeader* header, uint32_t parameter, uint32_t snapshot,
    uint32_t captured, bool sids);

template<class State>
void CaptureCatalogValues(State& call, Slot* slot, bool leaving, std::span<const ExportParameter> parameters,
    std::span<const ExportMember> members, uint32_t returnBufferBytes = 0, uint32_t countedResultBytes = 0,
    ExportValueKind resultCaptureKind = ExportValueKind::Bytes)
{
    auto header = call.transport->Header();
    auto partialNetApi = leaving && static_cast<uint32_t>(call.event.result) == ERROR_MORE_DATA &&
        std::any_of(parameters.begin(), parameters.end(), [](const auto& parameter)
    {
        return parameter.kind == ExportValueKind::NetApiRecords && (parameter.flags & ExportOutput) &&
            parameter.actualIndex;
    });

    // Structure results are read from the caller's hidden return buffer.
    if constexpr (requires { call.returnBuffer; })
    {
        if (leaving && returnBufferBytes && !(call.event.flags & Unwound))
            CopyValue(slot, header, UINT32_MAX, ValueKind::Bytes, call.returnBuffer, returnBufferBytes);
    }

    // Allocated message buffers expose a size-prefixed result under the same global capture limit.
    if (leaving && countedResultBytes && call.event.result && !(call.event.flags & Unwound))
    {
        uint32_t size = countedResultBytes;
        ReadCaptureMemory(reinterpret_cast<void*>(call.event.result), &size, sizeof(size));
        CopyValue(slot, header, UINT32_MAX, ValueKind::Bytes, call.event.result, size);
    }

    // Returned buffers use a reserved parent identity independently of fixed parameter positions.
    if (leaving && call.event.result && !(call.event.flags & (Failed | Skipped | Unwound)))
    {
        if (resultCaptureKind == ExportValueKind::BerValue)
            CaptureLdapBerValue(slot, header, ValueReturnedParameter, call.event.result);
        else if (resultCaptureKind == ExportValueKind::BerValues)
            CaptureLdapBerValues(slot, header, ValueReturnedParameter, call.event.result);
        else if (resultCaptureKind == ExportValueKind::Ansi || resultCaptureKind == ExportValueKind::Utf16)
        {
            CopyValue(slot, header, UINT32_MAX, resultCaptureKind == ExportValueKind::Utf16 ? ValueKind::Utf16 :
                ValueKind::Bytes, call.event.result, header->bufferLimit,
                {.terminated = true, .flags = ReferencedData});
        }
    }
    for (uint32_t index = 0; index < parameters.size(); ++index)
    {
        auto& parameter = parameters[index];
        if (!parameter.flags) continue;
        auto address = call.event.arguments[index];

        if (parameter.kind == ExportValueKind::PrintDocumentEvent)
        {
            CapturePrintDocumentEvent(call, slot, leaving, index, parameter);
            continue;
        }
        if (parameter.kind == ExportValueKind::AuthzOperations)
        {
            CaptureAuthzOperations(call, slot, leaving, index, parameter);
            continue;
        }
        if (parameter.kind == ExportValueKind::FailureEapError)
        {
            CaptureEapError(call, slot, leaving, index, parameter);
            continue;
        }
        if (parameter.kind == ExportValueKind::RtmBuffer)
        {
            CaptureRtmBuffer(call.event, slot, header, leaving, index, parameter);
            continue;
        }
        if (parameter.kind == ExportValueKind::PrinterPayload)
        {
            CapturePrinterPayload(call.event, slot, header, leaving, index, parameter);
            continue;
        }

        // Error arrays may be produced on failure; unchanged output pointers do not establish returned data.
        if (parameter.kind == ExportValueKind::SyncAllErrorsAnsi ||
            parameter.kind == ExportValueKind::SyncAllErrorsUtf16)
        {
            auto sample = uint32_t{1} << index;
            if (!leaving)
            {
                call.initializedOutputs &= ~sample;
                call.captureLimits[index] = 0;
                if (address && ReadCaptureMemory(reinterpret_cast<void*>(address),
                        call.captureLimits + index, sizeof(uintptr_t))) call.initializedOutputs |= sample;
                continue;
            }
            if (!address || !(parameter.flags & ExportOutput) || (call.event.flags & Skipped) ||
                (call.event.flags & Failed) && !(call.initializedOutputs & sample)) continue;
            auto pointer = slot->event.payloadBytes;
            address = CapturePointer(slot, header, index, address);
            if (slot->event.payloadBytes - pointer != sizeof(Value) + sizeof(uintptr_t)) continue;
            if ((call.event.flags & Failed) && address == call.captureLimits[index])
            {
                slot->event.payloadBytes = pointer;
                continue;
            }
            if (address) CaptureSyncAllErrors(slot, header, index, address,
                parameter.kind == ExportValueKind::SyncAllErrorsUtf16);
            continue;
        }
        // Successful NetAPI getters return one record; enumeration pages use their completed entry count.
        if (parameter.kind == ExportValueKind::NetApiRecords)
        {
            if (leaving && (parameter.flags & ExportOutput) && !(call.event.flags & (Skipped | Unwound)) &&
                (static_cast<uint32_t>(call.event.result) == 0 || partialNetApi) &&
                parameter.extentIndex >= 0 && static_cast<uint32_t>(parameter.extentIndex) < parameters.size() &&
                parameter.actualIndex <= parameters.size())
                CaptureNetApiRecords(slot, header, index, address,
                    parameter.actualIndex ? call.event.arguments[parameter.actualIndex - 1] : 0, parameter.bytes,
                    static_cast<uint32_t>(call.event.arguments[parameter.extentIndex]), !parameter.actualIndex);
            continue;
        }
        // Required-size scalars remain defined on capacity errors; failed data buffers do not.
        const bool requiredSize = parameter.kind == ExportValueKind::RequiredSize ||
            parameter.kind == ExportValueKind::RequiredSizeLastError;
        if (leaving && requiredSize &&
            (call.event.flags & (Skipped | Unwound))) continue;
        auto sizeFailure = parameter.kind == ExportValueKind::RequiredSize ?
            static_cast<uint32_t>(call.event.result) == ERROR_INSUFFICIENT_BUFFER ||
                static_cast<uint32_t>(call.event.result) == ERROR_BAD_LENGTH :
            parameter.kind == ExportValueKind::RequiredSizeLastError && (call.event.flags & Failed) &&
                call.event.error == ERROR_INSUFFICIENT_BUFFER;
        if (leaving && (call.event.flags & Failed) && !(parameter.flags & ExportInput) &&
            !partialNetApi && !sizeFailure) continue;
        if (leaving && (parameter.flags & ExportReturnedBuffer) &&
            (call.event.flags & (Skipped | Unwound | AsyncPending))) continue;
        if (leaving && (parameter.flags & ExportReturnedBuffer) && (call.event.flags & Failed) &&
            (parameter.kind == ExportValueKind::Utf16 || parameter.kind == ExportValueKind::Ansi ||
                parameter.kind == ExportValueKind::Utf16MultiString)) continue;
        if (leaving && (call.event.flags & (Skipped | Unwound)) &&
            (parameter.kind == ExportValueKind::SamRidEnumeration ||
             parameter.kind == ExportValueKind::SamSidEnumeration)) continue;
        if (!address) continue;
        if (!leaving && parameter.kind == ExportValueKind::Utf16StringArray)
        {
            call.captureLimits[index] = parameter.flags & ExportReturnedBuffer ? UINT64_MAX : 0;
            if (parameter.flags & ExportReturnedBuffer) continue;
        }

        // Authorization structures select bounded inputs and results independently of opaque handle identities.
        if (parameter.kind == ExportValueKind::AuthzReply)
        {
            if (parameter.extentIndex >= 0 && static_cast<uint32_t>(parameter.extentIndex) < parameters.size())
                CaptureAuthzReply(call, slot, leaving, index, call.event.arguments[parameter.extentIndex] != 0);
            continue;
        }
        if (parameter.kind == ExportValueKind::AuthzRequest || parameter.kind == ExportValueKind::SecurityDescriptor ||
            parameter.kind == ExportValueKind::SecurityDescriptors)
        {
            if (!leaving && (parameter.flags & ExportInput))
            {
                if (parameter.kind == ExportValueKind::AuthzRequest) CaptureAuthzRequest(slot, header, index, address);
                else if (parameter.kind == ExportValueKind::SecurityDescriptor)
                    CaptureSecurityDescriptor(slot, header, index, address, SecurityDescriptorData);
                else if (parameter.extentIndex >= 0 && static_cast<uint32_t>(parameter.extentIndex) < parameters.size())
                    CaptureSecurityDescriptors(slot, header, index, address,
                        static_cast<uint32_t>(call.event.arguments[parameter.extentIndex]));
            }
            continue;
        }
        if (parameter.kind == ExportValueKind::AuditParams || parameter.kind == ExportValueKind::Sid)
        {
            if (!leaving && (parameter.flags & ExportInput))
            {
                if (parameter.kind == ExportValueKind::AuditParams)
                    CaptureAuditParameters(slot, header, index, address);
                else CaptureSid(slot, header, index, address);
            }
            continue;
        }
        if (parameter.kind == ExportValueKind::ObjectAttributes || parameter.kind == ExportValueKind::IoStatus)
        {
            // Native descriptors retain their semantic shape and referenced object name under the capture limit.
            if (!(parameter.flags & (leaving ? ExportOutput : ExportInput))) continue;
            CopyValue(slot, header, index, parameter.kind == ExportValueKind::IoStatus ? ValueKind::IoStatus :
                ValueKind::ObjectAttributes, address, parameter.bytes);
            if (parameter.kind == ExportValueKind::ObjectAttributes)
            {
                uintptr_t name = 0;
                struct ObjectPrefix { uint32_t length; uintptr_t root, name; };
                CountedString text{};
                if (address <= UINTPTR_MAX - offsetof(ObjectPrefix, name) &&
                    ReadCaptureMemory(
                        reinterpret_cast<void*>(address + offsetof(ObjectPrefix, name)), &name, sizeof(name)) &&
                    name && ReadCaptureMemory(reinterpret_cast<void*>(name), &text, sizeof(text)))
                    CopyValue(slot, header, index, ValueKind::Utf16, text.buffer,
                        std::min(text.length, text.maximumLength));
            }
            continue;
        }

        // Sound flags select a name, resource identifier or RIFF buffer instead of one fixed pointer type.
        if (parameter.kind == ExportValueKind::SoundAnsi || parameter.kind == ExportValueKind::SoundUtf16)
        {
            if (!leaving && !(call.event.flags & Unwound) && parameter.extentIndex >= 0 &&
                static_cast<uint32_t>(parameter.extentIndex) < parameters.size())
                CaptureSoundValue(slot, header, index, address,
                    static_cast<uint32_t>(call.event.arguments[parameter.extentIndex]),
                    parameter.kind == ExportValueKind::SoundUtf16);
            continue;
        }

        if (parameter.kind == ExportValueKind::ReturnedSpan)
        {
            CaptureReturnedSpan(call, slot, leaving, index);
            continue;
        }

        // Certificate helpers expose an allocated descriptor and its bounded referenced fields.
        if (parameter.kind == ExportValueKind::X509Certificate)
        {
            if (!(parameter.flags & (leaving ? ExportOutput : ExportInput)) ||
                call.event.flags & (Skipped | Unwound)) continue;
            CaptureX509Certificate(slot, header, index, address, parameter.flags & ExportReturnedBuffer);
            continue;
        }

        // Marshalled arrays share Automation's bounded descriptor, dimension and element traversal.
        if (parameter.kind == ExportValueKind::SafeArray)
        {
            if (!(parameter.flags & (leaving ? ExportOutput : ExportInput)) ||
                call.event.flags & (Skipped | Unwound) ||
                leaving && (call.event.flags & Failed)) continue;
            if (parameter.flags & ExportByReference)
            {
                address = CapturePointer(slot, header, index, address);
            }
            CaptureAutomationArrays(slot, header, index, address, 0, true);
            continue;
        }

        // ETW descriptor arrays and inclusive classic buffers retain their bounded referenced payloads.
        if (parameter.kind == ExportValueKind::EtwDataDescriptors || parameter.kind == ExportValueKind::ClassicEtwEvent)
        {
            if (!(parameter.flags & (leaving ? ExportOutput : ExportInput)) ||
                call.event.flags & (Skipped | Unwound)) continue;
            if (parameter.kind == ExportValueKind::ClassicEtwEvent)
                CaptureClassicEtwEvent(slot, header, index, address, parameter.bytes);
            else if (parameter.extentIndex >= 0 && static_cast<uint32_t>(parameter.extentIndex) < parameters.size())
                CaptureEtwDescriptors(slot, header, index, address,
                    static_cast<uint32_t>(call.event.arguments[parameter.extentIndex]));
            continue;
        }

        if (parameter.kind == ExportValueKind::BerValues)
        {
            if ((parameter.flags & (leaving ? ExportOutput : ExportInput)) &&
                !(call.event.flags & (Skipped | Unwound)))
                CaptureLdapBerValues(slot, header, index, address);
            continue;
        }

        // LDAP cookies and controls follow only pointers retained in complete recorded descriptors.
        if (parameter.kind >= ExportValueKind::BerValue && parameter.kind <= ExportValueKind::LdapControlsUtf16)
        {
            if (!(parameter.flags & (leaving ? ExportOutput : ExportInput)) ||
                call.event.flags & (Skipped | Unwound)) continue;
            if (parameter.flags & ExportReturnedBuffer)
            {
                address = CapturePointer(slot, header, index, address);
                if (!address) continue;
            }
            if (parameter.kind == ExportValueKind::BerValue)
                CaptureLdapBerValue(slot, header, index, address);
            else CaptureLdapControls(slot, header, index, address,
                parameter.kind == ExportValueKind::LdapControlUtf16 ||
                    parameter.kind == ExportValueKind::LdapControlsUtf16,
                parameter.kind == ExportValueKind::LdapControlsAnsi ||
                    parameter.kind == ExportValueKind::LdapControlsUtf16);
            continue;
        }

        // Replication queries select a returned counted SDK structure using their information-class argument.
        if (parameter.kind == ExportValueKind::ReplicaInformation)
        {
            if (leaving && (parameter.flags & ExportOutput) && !(call.event.flags & Skipped) &&
                static_cast<uint32_t>(call.event.result) == 0)
                CaptureReplicationInformation(slot, header, index, address,
                    static_cast<uint32_t>(call.event.arguments[1]));
            continue;
        }

        // Restore maps use a signed element count and contain two bounded strings in each complete record.
        if (parameter.kind == ExportValueKind::AnsiStringPairs || parameter.kind == ExportValueKind::Utf16StringPairs)
        {
            if (!(parameter.flags & (leaving ? ExportOutput : ExportInput)) || parameter.extentIndex < 0) continue;
            auto count = static_cast<int32_t>(call.event.arguments[parameter.extentIndex]);
            if (parameter.flags & ExportReturnedBuffer)
            {
                if (!leaving || (call.event.flags & (Skipped | Unwound | Failed | AsyncPending)) ||
                    !ReadGuardedCaptureMemory(reinterpret_cast<const void*>(
                        call.event.arguments[parameter.extentIndex]), &count, sizeof(count))) continue;
                address = CapturePointer(slot, header, index, address, true);
            }
            if (count > 0)
                CaptureStringPairs(slot, header, index, address, static_cast<uint64_t>(count) * (2 * sizeof(uintptr_t)),
                    parameter.kind == ExportValueKind::Utf16StringPairs, true);
            continue;
        }

        // LDAP modification arrays select text or counted binary values in each descriptor.
        if (parameter.kind == ExportValueKind::LdapModAnsi || parameter.kind == ExportValueKind::LdapModUtf16)
        {
            if (parameter.flags & (leaving ? ExportOutput : ExportInput))
                CaptureLdapModifications(slot, header, index, address,
                    parameter.kind == ExportValueKind::LdapModUtf16);
            continue;
        }

        // Recipient lists derive their variable array extent from the completed structure itself.
        if (parameter.kind == ExportValueKind::MapiAddressList)
        {
            if (!leaving)
            {
                uint32_t count = 0;
                auto readable = !(parameter.flags & ExportReturnedBuffer) &&
                    ReadCaptureMemory(reinterpret_cast<void*>(address), &count, sizeof(count));
                call.captureLimits[index] = parameter.flags & ExportReturnedBuffer ? UINT64_MAX :
                    MapiAddressBytes(readable ? count : 0);
            }
            if (!(parameter.flags & (leaving ? ExportOutput : ExportInput))) continue;
            if (parameter.flags & ExportReturnedBuffer)
            {
                CopyValue(slot, header, index, ValueKind::Scalar, address, sizeof(uintptr_t));
                uintptr_t returned = 0;
                if (!ReadCaptureMemory(reinterpret_cast<void*>(address), &returned, sizeof(returned))) continue;
                address = returned;
            }
            if (address) CaptureMapiAddressList(slot, header, index, address, call.captureLimits[index]);
            continue;
        }

        // Automation and WinRT strings carry their own lengths, including newly allocated output values.
        if (parameter.kind == ExportValueKind::Bstr || parameter.kind == ExportValueKind::HString)
        {
            if (!(parameter.flags & (leaving ? ExportOutput : ExportInput))) continue;
            if (parameter.flags & ExportByReference)
            {
                CopyValue(slot, header, index, ValueKind::Scalar, address, sizeof(uintptr_t));
                uintptr_t value = 0;
                if (!ReadCaptureMemory(reinterpret_cast<void*>(address), &value, sizeof(value))) continue;
                address = value;
            }
            if (parameter.kind == ExportValueKind::Bstr)
            {
                uint32_t length = 0;
                if (address >= sizeof(length) && ReadCaptureMemory(
                    reinterpret_cast<void*>(address - sizeof(length)), &length, sizeof(length)))
                    CopyValue(slot, header, index, ValueKind::Utf16, address, length);
            }
            else
            {
                HStringHeader string{};
                if (address && ReadCaptureMemory(reinterpret_cast<void*>(address), &string, sizeof(string)))
                    CopyValue(slot, header, index, ValueKind::Utf16, string.data, uint64_t{string.length} * 2);
            }
            continue;
        }

        // Counted strings expose only their declared length, without scanning or unrelated argument slots.
        if (parameter.kind == ExportValueKind::UnicodeString || parameter.kind == ExportValueKind::AnsiString)
        {
            if (!(parameter.flags & (leaving ? ExportOutput : ExportInput))) continue;
            CountedString text{};
            if (ReadCaptureMemory(reinterpret_cast<void*>(address), &text, sizeof(text)))
            {
                CopyValue(slot, header, index, ValueKind::Bytes, reinterpret_cast<uint64_t>(&text), sizeof(text));
                CopyValue(slot, header, index, parameter.kind == ExportValueKind::UnicodeString ?
                    ValueKind::Utf16 : ValueKind::Bytes, text.buffer, std::min(text.length, text.maximumLength),
                    {.flags = ReferencedData});
            }
            else CopyValue(slot, header, index, ValueKind::Bytes, address, sizeof(text));
            continue;
        }
        uint64_t length = parameter.bytes;
        bool terminated = (parameter.flags & ExportTerminated) != 0;
        if (parameter.kind == ExportValueKind::CountedBytes)
        {
            uint32_t size = 0;
            auto offset = parameter.actualIndex ? 0 : parameter.actualOffset;
            if (offset && (address > UINTPTR_MAX - offset || !ReadGuardedCaptureMemory(
                    reinterpret_cast<void*>(address + offset), &size, sizeof(size)))) continue;
            if (offset || ReadCaptureMemory(reinterpret_cast<void*>(address), &size, sizeof(size))) length = size;
        }
        if (parameter.extentIndex >= 0)
        {
            length = call.event.arguments[parameter.extentIndex];
            if (parameter.flags & ExportNegativeTerminated && static_cast<int32_t>(length) < 0)
            {
                length = header->bufferLimit;
                terminated = true;
            }
            if (parameter.indirectBytes)
            {
                uint64_t value = 0;
                if (!(parameter.kind == ExportValueKind::Utf16StringArray ?
                    ReadGuardedCaptureMemory(reinterpret_cast<void*>(length), &value, parameter.indirectBytes) :
                    ReadCaptureMemory(reinterpret_cast<void*>(length), &value, parameter.indirectBytes))) continue;
                length = value;
            }
            if (parameter.productIndex)
            {
                auto factor = call.event.arguments[parameter.productIndex - 1];
                length = factor && length > UINT64_MAX / factor ? UINT64_MAX : length * factor;
            }
            length = length > UINT64_MAX / parameter.multiplier ? UINT64_MAX : length * parameter.multiplier;
        }
        else if (parameter.extentIndex == -2)
        {
            length = leaving ? call.event.result : UINT64_MAX;
            if (leaving)
                length = length > UINT64_MAX / parameter.multiplier ? UINT64_MAX : length * parameter.multiplier;
        }
        length = length > UINT64_MAX - parameter.prefixBytes ? UINT64_MAX : length + parameter.prefixBytes;
        if (terminated) length = std::min<uint64_t>(length, header->bufferLimit);
        if (!leaving) call.captureLimits[index] = parameter.flags & ExportReturnedBuffer ? UINT64_MAX : length;
        else length = std::min(length, call.captureLimits[index]);
        if (!(parameter.flags & (leaving ? ExportOutput : ExportInput))) continue;
        if (leaving && parameter.actualIndex)
        {
            auto actual = parameter.actualIndex == ExportActualReturn ? call.event.result :
                call.event.arguments[parameter.actualIndex - 1];
            if (parameter.actualIndirectBytes)
            {
                uint64_t value = 0;
                if (actual <= UINT64_MAX - parameter.actualOffset &&
                    (parameter.kind == ExportValueKind::Utf16StringArray ?
                        ReadGuardedCaptureMemory(reinterpret_cast<void*>(actual + parameter.actualOffset),
                            &value, parameter.actualIndirectBytes) :
                        ReadCaptureMemory(reinterpret_cast<void*>(actual + parameter.actualOffset),
                            &value, parameter.actualIndirectBytes)))
                    actual = value;
                else if ((parameter.flags & ExportInterfaceArray) ||
                    parameter.kind == ExportValueKind::Utf16StringArray) continue;
                else actual = length / parameter.multiplier;
            }
            actual = actual > UINT64_MAX / parameter.multiplier ? UINT64_MAX : actual * parameter.multiplier;
            actual = actual > UINT64_MAX - parameter.actualPrefixBytes ? UINT64_MAX :
                actual + parameter.actualPrefixBytes;
            length = std::min(length, actual);
        }
        if (!length && (parameter.actualIndex || parameter.extentIndex == -1 && !parameter.bytes) &&
            parameter.kind != ExportValueKind::IndirectBytes && !(parameter.flags & ExportInterfaceArray)) continue;
        if (parameter.kind == ExportValueKind::IndirectBytes || parameter.flags & ExportReturnedBuffer)
        {
            if (parameter.kind == ExportValueKind::Utf16StringArray ||
                (parameter.kind == ExportValueKind::Utf16 || parameter.kind == ExportValueKind::Ansi ||
                    parameter.kind == ExportValueKind::Utf16MultiString) && terminated)
                address = CapturePointer(slot, header, index, address, true);
            else
            {
                CopyValue(slot, header, index, ValueKind::Scalar, address, sizeof(uintptr_t));
                uintptr_t value = 0;
                if (!ReadCaptureMemory(reinterpret_cast<void*>(address), &value, sizeof(value))) continue;
                address = value;
            }
            if (!address) continue;
        }
        auto kind = parameter.kind == ExportValueKind::Utf16 || parameter.kind == ExportValueKind::Utf16MultiString ?
            ValueKind::Utf16 : parameter.kind == ExportValueKind::Scalar || requiredSize ?
                ValueKind::Scalar : ValueKind::Bytes;
        if (parameter.kind == ExportValueKind::Ansi && !terminated &&
            !(parameter.flags & ExportNegativeTerminated))
        {
            auto limit = std::min<uint64_t>(length, header->bufferLimit);
            for (uint64_t offset = 0; offset < limit; ++offset)
            {
                char character = 0;
                if (!ReadCaptureMemory(reinterpret_cast<const char*>(address) + offset, &character, 1)) break;
                if (!character) { length = offset + 1; break; }
            }
        }
        const bool text = kind == ValueKind::Utf16 || parameter.kind == ExportValueKind::Ansi;
        const bool multiString = parameter.kind == ExportValueKind::Utf16MultiString;
        const bool returnedText = (parameter.flags & ExportReturnedBuffer) && terminated && text;
        auto snapshotOffset = slot->event.payloadBytes;
        auto capturedBytes = CopyValue(slot, header, index, kind, address, length,
            {.terminated = terminated && text, .multiString = multiString,
             .guarded = parameter.kind == ExportValueKind::Utf16StringArray || returnedText ||
                 parameter.kind == ExportValueKind::RequiredSizeLastError ||
                 parameter.kind == ExportValueKind::CountedBytes && parameter.actualOffset && !parameter.actualIndex,
             .flags = returnedText ? ReferencedData : 0u});

        if (parameter.kind == ExportValueKind::SamRidEnumeration ||
            parameter.kind == ExportValueKind::SamSidEnumeration)
            CaptureSamReferences(slot, header, index, snapshotOffset, capturedBytes,
                parameter.kind == ExportValueKind::SamSidEnumeration);

        // Typed variant buffers share bounded reference traversal with Automation enumeration.
        if ((parameter.flags & ExportAutomationVariant) || parameter.kind == ExportValueKind::PropertyVariant)
            CaptureAutomationBuffer(slot, header, index, address, snapshotOffset,
                parameter.extentIndex == -1 && parameter.bytes == sizeof(VARIANT),
                parameter.kind == ExportValueKind::PropertyVariant);
        if (parameter.kind == ExportValueKind::BstrArray && capturedBytes)
        {
            // Counted BSTR arrays retain text only for complete pointers inside the captured array region.
            auto count = std::min<uint32_t>(capturedBytes / sizeof(BSTR), UINT16_MAX + 1u);
            for (uint32_t element = 0; element < count; ++element)
            {
                uintptr_t string = 0;
                uint32_t bytes = 0;
                if (!ReadCaptureMemory(reinterpret_cast<void*>(address + uint64_t{element} * sizeof(BSTR)),
                    &string, sizeof(string))) break;
                bool readable = !string || string >= sizeof(bytes) &&
                    ReadCaptureMemory(reinterpret_cast<void*>(string - sizeof(bytes)), &bytes, sizeof(bytes));
                auto offset = slot->event.payloadBytes;
                CopyValue(slot, header, index, ValueKind::Utf16, string && readable ? string : address,
                    readable ? bytes : 0, {.flags = StringArrayElement | ReferencedData | (element << ValueDetailShift) |
                        (readable ? 0u : Unreadable)});
                if (slot->event.payloadBytes == offset) break;
            }
        }
        if (parameter.kind == ExportValueKind::Utf16StringArray && capturedBytes)
        {
            const auto data = Transport::Payload(slot) + snapshotOffset + sizeof(Value);
            const auto count = std::min<uint32_t>(capturedBytes / parameter.multiplier, UINT16_MAX + 1u);
            for (uint32_t element = 0; element < count; ++element)
            {
                uintptr_t string = 0;
                memcpy(&string, data + element * parameter.multiplier + parameter.actualOffset, sizeof(string));
                if (!string) continue;
                auto offset = slot->event.payloadBytes;
                CopyValue(slot, header, index, ValueKind::Utf16, string, header->bufferLimit,
                    {.terminated = true, .guarded = true,
                     .flags = StringArrayElement | ReferencedData | (element << ValueDetailShift)});
                if (slot->event.payloadBytes == offset) break;
            }
        }
        if (parameter.kind == ExportValueKind::MapiPropertyArray)
            CaptureMapiProperties(slot, header, index, snapshotOffset);
    }

    // Bound referenced structure buffers by caller capacities unless the API allocates the returned storage.
    for (uint32_t index = 0; index < members.size(); ++index)
    {
        const auto& member = members[index];
        auto& capacity = call.captureLimits[parameters.size() + index];
        if (!leaving) capacity = 0;
        if (member.flags & ExportIndirectSelector)
        {
            uint32_t selector = 0;
            if (!leaving || (call.event.flags & (Skipped | Unwound | Failed | AsyncPending)) ||
                !member.conditionIndex ||
                !ReadGuardedCaptureMemory(reinterpret_cast<const void*>(
                    call.event.arguments[member.conditionIndex - 1]), &selector, sizeof(selector)) ||
                selector != member.conditionMask) continue;
        }
        else if (member.conditionIndex && !(call.event.arguments[member.conditionIndex - 1] & member.conditionMask))
            continue;
        if (!leaving && !(member.flags & ExportInput) && (member.flags & ExportReturnedBuffer)) continue;
        if (leaving && (call.event.flags & (Skipped | Unwound)) ||
            leaving && (call.event.flags & (Failed | AsyncPending)) &&
                (!(member.flags & ExportInput) || (member.flags & ExportIndirectRecord))) continue;
        const bool inlineRecord = (member.flags & ExportInlineRecord) != 0;
        if (inlineRecord && (uint64_t{member.pointerOffset} + sizeof(uintptr_t) > sizeof(uint64_t) ||
                uint64_t{member.extentOffset} + member.extentBytes > sizeof(uint64_t) ||
                uint64_t{member.productOffset} + member.productBytes > sizeof(uint64_t))) continue;
        if (member.flags & ExportTerminated)
        {
            if ((member.flags & (leaving ? ExportOutput : ExportInput)) && !(call.event.flags & (Skipped | Unwound)) &&
                !(leaving && (call.event.flags & (Failed | AsyncPending))))
            {
                if (!inlineRecord)
                    CaptureStringMember(slot, header, member.parameter, member.pointerOffset, member.multiplier == 2);
                else
                {
                    uintptr_t pointer = 0;
                    memcpy(&pointer, reinterpret_cast<const uint8_t*>(&call.event.arguments[member.parameter]) +
                        member.pointerOffset, sizeof(pointer));
                    CopyValue(slot, header, PackMemberParameter(member.parameter, member.pointerOffset),
                        member.multiplier == 2 ? ValueKind::Utf16 : ValueKind::Bytes, pointer, header->bufferLimit,
                        {.terminated = true, .guarded = true, .flags = MemberData | ReferencedData});
                }
            }
            continue;
        }
        uintptr_t pointer = 0;
        uint64_t count = 0;
        const std::byte* record = inlineRecord ?
            reinterpret_cast<const std::byte*>(&call.event.arguments[member.parameter]) : nullptr;
        std::byte live[256];
        if (!record)
        {
            const auto needed = std::max(uint64_t{member.pointerOffset} + sizeof(pointer),
                std::max(uint64_t{member.extentOffset} + member.extentBytes,
                    uint64_t{member.productOffset} + member.productBytes));
            bool truncated = false;
            for (uint32_t offset = 0; offset + sizeof(Value) <= slot->event.payloadBytes;)
            {
                Value parent{};
                memcpy(&parent, Transport::Payload(slot) + offset, sizeof(parent));
                if (parent.parameter == member.parameter && parent.kind == ValueKind::Bytes &&
                    !(parent.flags & MemberData))
                {
                    if (parent.capturedBytes >= needed)
                    {
                        record = Transport::Payload(slot) + offset + sizeof(parent);
                        break;
                    }
                    truncated |= parent.originalBytes >= needed;
                }
                offset += static_cast<uint32_t>(sizeof(parent)) + parent.capturedBytes;
            }

            // A buffer limit can truncate a caller's record before its extent field; returned records stay bounded
            // by what was captured, so only direct records are read again.
            if (!record && truncated && !(member.flags & (ExportReturnedBuffer | ExportIndirectRecord)) &&
                needed <= sizeof(live) && ReadGuardedCaptureMemory(
                    reinterpret_cast<const void*>(call.event.arguments[member.parameter]), live,
                    static_cast<size_t>(needed)))
                record = live;
        }
        if (!record) continue;
        memcpy(&pointer, record + member.pointerOffset, sizeof(pointer));
        memcpy(&count, record + member.extentOffset, member.extentBytes);
        if (member.productBytes)
        {
            uint64_t factor = 0;
            memcpy(&factor, record + member.productOffset, member.productBytes);
            count = factor && count > UINT64_MAX / factor ? UINT64_MAX : count * factor;
        }
        auto length = count > UINT64_MAX / member.multiplier ? UINT64_MAX : count * member.multiplier;
        if (!leaving) capacity = length;
        else if (member.flags & ExportAdvancingBuffer)
        {

            // Streaming APIs advance the pointer and reduce the remaining capacity by the completed byte count.
            if (length > capacity || pointer < capacity - length) continue;
            pointer -= static_cast<uintptr_t>(capacity - length);
            length = capacity - length;
        }
        else if (!(member.flags & ExportReturnedBuffer)) length = std::min(length, capacity);
        if (!pointer || !length || !(member.flags & (leaving ? ExportOutput : ExportInput)) ||
            leaving && (call.event.flags & (Failed | AsyncPending)) && !(member.flags & ExportInput)) continue;
        auto identity = PackMemberParameter(member.parameter, member.pointerOffset);
        CopyValue(slot, header, identity, ValueKind::Bytes, pointer, length, {.guarded = true, .flags = MemberData});
    }
}
}
