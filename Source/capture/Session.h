#pragma once
#include "TraceStore.h"
#include "ManagedAttach.h"
#include <atomic>
#include <mutex>
#include <thread>
#include <optional>
#include <future>
#include <functional>
#include <semaphore>

namespace Detourist
{
struct CaptureOptions
{
    uint32_t bufferLimit = DefaultBufferLimit;
    uint32_t traceStopMiB = 0;
    uint32_t stackDepth = 0;
    uint64_t apiMask = AllApis;
    uint64_t categoryMask = AllCategories;
    std::vector<std::string> excludedApis;
    std::vector<uint32_t> expectedExitCodes;
    uint64_t entryBreaks = 0;
    uint64_t exitBreaks = 0;
    int32_t entryApi = -1;
    int32_t exitApi = -1;
    bool followChildren = true;
    bool instructionEngine = false;
    bool rawPointerProbes = false;
    bool startMinimized = false;
    std::wstring workingDirectory;
};

struct SessionStatus
{
    bool finished = false;
    bool capturing = false;
    bool breakpoint = false;
    bool partial = false;
    uint64_t calls = 0;
    uint64_t records = 0;
    uint64_t queued = 0;
    uint32_t processes = 0;
    uint32_t skippedChildren = 0;
    double blockedMilliseconds = 0;
    std::wstring message = L"Preparing capture…";
    Event stoppedCall{};
    DynamicApiMetadata stoppedDefinition{};
    int64_t stoppedTarget = 0;
    uint32_t stoppedPointerSize = 0;
    bool leaving = false;
    uint32_t attaching = 0;
};

void BootstrapTarget(DWORD pid, DWORD primaryThreadId, bool initializeLoader, bool launched, bool instructionEngine,
    const std::wstring& mappingName, HANDLE cancellation = nullptr,
    const std::function<void(bool)>& progress = {});

class Session
{
public:
    Session(const std::wstring& database, const CaptureOptions& options, uint32_t attachPid,
        std::wstring executable = {}, std::wstring arguments = {});
    ~Session();
    SessionStatus Status() const;
    void Stop();
    void Pause(bool paused);
    void SetFilters(uint64_t mask, uint64_t categories = AllCategories);
    void SetExcludedApis(const std::vector<std::string>& names);
    void SetBreaks(uint64_t entry, uint64_t exit);
    void SetApiBreaks(int32_t entry, int32_t exit);
    void Continue(const Event& editedCall, bool skip);
    bool WriteMemory(uint64_t address, const void* bytes, size_t length, std::wstring& error);
    bool ReadMemory(uint64_t address, size_t length, std::vector<uint8_t>& bytes, std::wstring& error);
    uint32_t BufferLimit() const { return options_.bufferLimit; }
    const std::wstring& Database() const { return databasePath_; }
private:
    enum class TargetPhase { Recording, Draining };
    enum class AttachmentProgress : LONG { Starting, ApcQueued, LoaderReady };
    static constexpr ptrdiff_t MaxConcurrentAttachments = 4;
    struct Target
    {
        ~Target() { transport.Stop(); breakpointSuspension.reset(); }
        int64_t id = 0;
        DWORD pid = 0;
        uint32_t pointerSize = sizeof(void*);
        Handle process;
        Transport transport;
        Handle breakpointSuspension;
        TargetPhase phase = TargetPhase::Recording;
        std::wstring image;
        int64_t parent = 0;
        uint64_t exclusionGeneration = 0;
        std::future<ManagedAttachment> managedAttach;
        std::unique_ptr<ManagedDebugger> managedDebugger;
        std::future<HRESULT> detaching;
        uint64_t nextManagedProbe = 0;
        bool probeManaged = false;
        std::unordered_set<uint64_t> modules;
        uint64_t nextModules = 0;
        uint32_t moduleInterval = 10;
    };
    struct Attachment
    {
        ChildRequest* request;
        int64_t parent;
        DWORD pid;
        std::shared_ptr<std::atomic<LONG>> progress;
        std::future<std::unique_ptr<Target>> result;
    };
    void Run(uint32_t attachPid, std::wstring executable, std::wstring arguments);
    std::unique_ptr<Target> PrepareTarget(DWORD pid, int64_t parent, bool launched, DWORD primaryThreadId = 0,
        bool suspended = false, std::shared_ptr<std::atomic<LONG>> progress = {});
    void SyncBreaks(SharedHeader* header) const;
    void RegisterTarget(std::unique_ptr<Target> target);
    void RecordSkippedChild(int64_t parent, DWORD pid, const std::wstring& reason);
    void CompleteAttachments(bool wait = false);
    void ApplyExclusions(Target& target);
    void RecordModules(Target& target);
    void RecordModuleChanges(Target& target);
    void PumpDebugger();
    void PublishStatus(const std::wstring& message = {});
    std::wstring databasePath_;
    CaptureOptions options_;
    mutable std::mutex mutex_;
    SessionStatus status_;
    std::vector<uint64_t> excludedApis_;
    std::atomic<uint64_t> exclusionGeneration_ = 1;
    std::vector<std::unique_ptr<Target>> targets_;
    std::vector<Attachment> attachments_;
    std::counting_semaphore<MaxConcurrentAttachments> attachmentSlots_{MaxConcurrentAttachments};
    std::unique_ptr<TraceStore> store_;
    uint32_t totalProcesses_ = 0;
    uint32_t skippedChildren_ = 0;
    uint64_t retiredRecords_ = 0;
    double retiredBlockedMilliseconds_ = 0;
    std::atomic<bool> stop_ = false;
    std::atomic<bool> forceStop_ = false;
    std::atomic<bool> paused_ = false;
    std::atomic<uint64_t> filters_, entryBreaks_, exitBreaks_;
    std::atomic<int32_t> entryApi_, exitApi_;
    std::atomic<bool> resumeRequested_ = false;
    Event editedCall_{};
    bool skipCall_ = false;
    bool profilerLaunch_ = false;
    Handle cancelAttach_{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::jthread worker_;
};
}
