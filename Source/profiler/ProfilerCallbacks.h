#pragma once
#include <windows.h>
#include <cor.h>
#include <corprof.h>

namespace Detourist
{
// Unsubscribed CLR notifications have no effect on the target.
class ProfilerCallbacks : public ICorProfilerCallback4
{
public:
    HRESULT STDMETHODCALLTYPE ReJITCompilationStarted(FunctionID, ReJITID, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AppDomainCreationStarted(AppDomainID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AppDomainCreationFinished(AppDomainID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AppDomainShutdownStarted(AppDomainID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AppDomainShutdownFinished(AppDomainID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AssemblyLoadStarted(AssemblyID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AssemblyUnloadStarted(AssemblyID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AssemblyUnloadFinished(AssemblyID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ModuleLoadStarted(ModuleID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ModuleUnloadStarted(ModuleID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ModuleAttachedToAssembly(ModuleID, AssemblyID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ClassLoadStarted(ClassID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ClassUnloadFinished(ClassID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchFinished(FunctionID, COR_PRF_JIT_CACHE) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITFunctionPitched(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ThreadCreated(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ThreadDestroyed(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ThreadAssignedToOSThread(ThreadID, DWORD) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingClientInvocationStarted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingClientSendingMessage(GUID *, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingClientReceivingReply(GUID *, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingClientInvocationFinished() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerReceivingMessage(GUID *, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerInvocationStarted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerInvocationReturned() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerSendingReply(GUID *, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE UnmanagedToManagedTransition(FunctionID,
        COR_PRF_TRANSITION_REASON) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ManagedToUnmanagedTransition(FunctionID,
        COR_PRF_TRANSITION_REASON) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeSuspendStarted(COR_PRF_SUSPEND_REASON) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeSuspendFinished() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeSuspendAborted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeResumeStarted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeResumeFinished() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeThreadSuspended(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeThreadResumed(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ObjectAllocated(ObjectID, ClassID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ObjectsAllocatedByClass(ULONG, ClassID [ ], ULONG [ ]) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ObjectReferences(ObjectID, ClassID, ULONG, ObjectID [ ]) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RootReferences(ULONG, ObjectID [ ]) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionThrown(ObjectID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionEnter(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFilterEnter(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFilterLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchCatcherFound(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionOSHandlerEnter(UINT_PTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionOSHandlerLeave(UINT_PTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFinallyEnter(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFinallyLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCatcherEnter(FunctionID, ObjectID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCatcherLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE COMClassicVTableCreated(ClassID, REFGUID, void *, ULONG) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE COMClassicVTableDestroyed(ClassID, REFGUID, void *) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCLRCatcherFound() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCLRCatcherExecute() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ThreadNameChanged(ThreadID, ULONG, WCHAR [ ]) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE FinalizeableObjectQueued(DWORD, ObjectID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RootReferences2(
        ULONG, ObjectID[], COR_PRF_GC_ROOT_KIND[], COR_PRF_GC_ROOT_FLAGS[], UINT_PTR[]) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE HandleCreated(GCHandleID, ObjectID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE HandleDestroyed(GCHandleID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ProfilerDetachSucceeded() override { return S_OK; }
};
}

