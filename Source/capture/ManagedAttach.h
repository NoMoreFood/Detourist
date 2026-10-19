#pragma once
#include "Transport.h"
#include <memory>

namespace Detourist
{
class ManagedDebugger
{
public:
    virtual ~ManagedDebugger() = default;
    // Observers apply capture filter changes that their instrumentation depends on.
    virtual void Refresh() {}
    virtual HRESULT Shutdown() = 0;
};

struct ManagedAttachment
{
    HRESULT result = S_FALSE;
    std::unique_ptr<ManagedDebugger> debugger;
};

// S_FALSE means no managed runtime has loaded yet.
ManagedAttachment AttachManagedProfiler(DWORD processId, Transport& transport, uint32_t pointerSize = sizeof(void*));
std::unique_ptr<ManagedDebugger> AttachManagedDebugger(DWORD processId, Transport& transport,
    const std::wstring& runtime, bool legacy, HRESULT& result);
}
