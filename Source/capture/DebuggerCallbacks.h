#pragma once
#include <cordebug.h>
#include <wrl/client.h>

namespace Detourist
{
// Resume runtime notifications that do not contribute API records.
class DebuggerCallbacks : public ICorDebugManagedCallback, public ICorDebugManagedCallback2
{
public:
    HRESULT STDMETHODCALLTYPE StepComplete(ICorDebugAppDomain* domain, ICorDebugThread*, ICorDebugStepper*,
        CorDebugStepReason) override { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE Break(ICorDebugAppDomain* domain, ICorDebugThread*) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE Exception(ICorDebugAppDomain* domain, ICorDebugThread*, BOOL) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE EvalComplete(ICorDebugAppDomain* domain, ICorDebugThread*, ICorDebugEval*) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE EvalException(ICorDebugAppDomain* domain, ICorDebugThread*, ICorDebugEval*) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE CreateThread(ICorDebugAppDomain* domain, ICorDebugThread*) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE UnloadModule(ICorDebugAppDomain* domain, ICorDebugModule*) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE LoadClass(ICorDebugAppDomain* domain, ICorDebugClass*) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE UnloadClass(ICorDebugAppDomain* domain, ICorDebugClass*) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE LogMessage(ICorDebugAppDomain* domain, ICorDebugThread*, LONG, WCHAR*, WCHAR*) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE LogSwitch(ICorDebugAppDomain* domain, ICorDebugThread*, LONG, ULONG, WCHAR*,
        WCHAR*) override { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE CreateAppDomain(ICorDebugProcess* process, ICorDebugAppDomain* domain) override
    {
        domain->Attach();
        return process->Continue(FALSE);
    }
    HRESULT STDMETHODCALLTYPE ExitAppDomain(ICorDebugProcess*, ICorDebugAppDomain* domain) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE LoadAssembly(ICorDebugAppDomain* domain, ICorDebugAssembly*) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE UnloadAssembly(ICorDebugAppDomain* domain, ICorDebugAssembly*) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE ControlCTrap(ICorDebugProcess* process) override { return process->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE NameChange(ICorDebugAppDomain* domain, ICorDebugThread* thread) override
    {
        if (domain) return domain->Continue(FALSE);
        Microsoft::WRL::ComPtr<ICorDebugProcess> process;
        return thread && SUCCEEDED(thread->GetProcess(&process)) ? process->Continue(FALSE) : S_OK;
    }
    HRESULT STDMETHODCALLTYPE UpdateModuleSymbols(ICorDebugAppDomain* domain, ICorDebugModule*, IStream*) override
    { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE EditAndContinueRemap(ICorDebugAppDomain* domain, ICorDebugThread*,
        ICorDebugFunction*, BOOL) override { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE BreakpointSetError(ICorDebugAppDomain* domain, ICorDebugThread*,
        ICorDebugBreakpoint*, DWORD) override { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE FunctionRemapOpportunity(ICorDebugAppDomain* domain, ICorDebugThread*,
        ICorDebugFunction*, ICorDebugFunction*, ULONG32) override { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE CreateConnection(ICorDebugProcess* process, CONNID, WCHAR*) override
    { return process->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE ChangeConnection(ICorDebugProcess* process, CONNID) override
    { return process->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE DestroyConnection(ICorDebugProcess* process, CONNID) override
    { return process->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE Exception(ICorDebugAppDomain* domain, ICorDebugThread*, ICorDebugFrame*,
        ULONG32, CorDebugExceptionCallbackType, DWORD) override { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE ExceptionUnwind(ICorDebugAppDomain* domain, ICorDebugThread*,
        CorDebugExceptionUnwindCallbackType, DWORD) override { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE FunctionRemapComplete(ICorDebugAppDomain* domain, ICorDebugThread*,
        ICorDebugFunction*) override { return domain->Continue(FALSE); }
    HRESULT STDMETHODCALLTYPE MDANotification(ICorDebugController* controller, ICorDebugThread*,
        ICorDebugMDA*) override { return controller->Continue(FALSE); }
};
}
