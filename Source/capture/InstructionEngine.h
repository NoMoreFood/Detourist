#pragma once
#include "Transport.h"

namespace Detourist
{
uintptr_t RemoteSystemProcedure(DWORD pid, void* procedure);
DWORD RemoteInvoke(HANDLE process, uintptr_t procedure, const std::wstring& text, HANDLE cancellation,
    HANDLE startupToken);
uintptr_t LoadCaptureAgent(HANDLE process, DWORD pid, const std::wstring& path, HANDLE cancellation,
    HANDLE startupToken);

void StartInstructionEngine(DWORD pid, uint64_t mapping, SharedHeader& header, bool launched,
    HANDLE startupToken, uintptr_t agentBase = 0);
void StopInstructionEngine(DWORD pid, SharedHeader& header);
}
