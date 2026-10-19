#pragma once
#include "CatalogView.h"
#include "WinSupport.h"
#include <span>
#include <vector>

namespace Detourist
{
struct RecordView
{
    const Event& event;
    std::span<const std::byte> payload;
};

struct Record
{
    Event event{};
    std::vector<std::byte> payload;
    operator RecordView() const { return {event, payload}; }
};

class Transport
{
public:
    ~Transport();
    Transport() = default;
    explicit Transport(TransportStartup& startup) noexcept;
    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;
    void Create(const std::wstring& name, uint32_t processId, uint32_t bufferLimit, uint32_t stackDepth,
        uint64_t captureMask, bool followChildren, const std::wstring& catalogName = {});
    bool Open(const std::wstring& name, uint32_t processId = 0, bool bindCatalog = true);
    bool Open(uint64_t captureIdentity, bool bindCatalog = true);
    bool Open(HANDLE mapping, uint64_t captureIdentity, bool bindCatalog = true);
    TransportHandles DuplicateTo(HANDLE process, HANDLE startupThread = nullptr) const;
    static void CloseRemote(HANDLE process, const TransportHandles& handles);
    Slot* Acquire();
    void Publish(Slot* slot);
    bool Read(Record& record);
    // Borrowed records remain valid until their consumer returns.
    template<class Consumer>
    uint32_t ReadBatch(uint32_t limit, const Consumer& consume)
    {
        return ReadBatch(limit, &consume, [](const void* context, const RecordView& record)
        {
            (*static_cast<const Consumer*>(context))(record);
        });
    }
    bool CollectorAlive() const;
    LONG RequestThreadIds(DWORD* ids, DWORD capacity, DWORD* count) noexcept;
    void ServiceThreadIds(HANDLE process, DWORD pid) noexcept;
    void Stop();
    SharedHeader* Header() const { return header_; }
    const CatalogView& Catalog() const { return catalog_; }
    const std::wstring& Name() const { return name_; }
    HANDLE DataEvent() const { return data_.get(); }
    HANDLE ReadyEvent() const { return ready_.get(); }
    HANDLE ResumeEvent() const { return resume_.get(); }
    HANDLE BreakEvent() const { return break_.get(); }
    HANDLE BootstrapReleaseEvent() const { return bootstrapRelease_.get(); }
    HANDLE StartupThread() const { return startupThread_.get(); }
    static std::byte* Payload(Slot* slot) { return reinterpret_cast<std::byte*>(slot) + sizeof(Slot); }
private:
    bool BindEvents(bool create);
    bool Map(uint32_t processId, uint64_t captureIdentity = 0);
    bool MapCatalog(bool bindCatalog);
    uint32_t ReadBatch(uint32_t limit, const void* context, void (*consume)(const void*, const RecordView&));
    SharedHeader* header_ = nullptr;
    uint32_t readHead_ = 0;
    std::wstring name_;
    Handle mapping_, data_, space_, ready_, resume_, break_, controller_, bootstrapRelease_;
    Handle catalogMapping_, startupThread_;
    void* catalogView_ = nullptr;
    CatalogView catalog_;
};
}
