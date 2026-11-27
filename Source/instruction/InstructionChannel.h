#pragma once
#include "Protocol.h"
#include "CatalogView.h"

namespace Detourist
{
struct InstructionChannel
{
    SharedHeader* header = nullptr;
    HANDLE section = nullptr, data = nullptr, space = nullptr, controller = nullptr;
    HANDLE resume = nullptr, breakpoint = nullptr;
    HANDLE catalogSection = nullptr;
    void* catalogMemory = nullptr;
    CatalogView catalog;
    bool Open(uint64_t mapping, uint64_t captureIdentity);
    void Close();
    bool CollectorAlive() const;
    Slot* Acquire();
    void Publish(Slot* slot);
    SharedHeader* Header() const { return header; }
    const CatalogView& Catalog() const { return catalog; }
    static std::byte* Payload(Slot* slot)
    {
        return reinterpret_cast<std::byte*>(slot) + sizeof(Slot) + slot->bufferDelta + slot->payloadOffset;
    }
};
}
