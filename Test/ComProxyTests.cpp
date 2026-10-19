#include "TestSupport.h"

using namespace Detourist::Tests;
using Microsoft::WRL::ComPtr;

class ProxyChannel final : public IRpcChannelBuffer
{
public:
    ULONG requests = 0;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == IID_IUnknown || iid == IID_IRpcChannelBuffer ? this : nullptr;
        if (*output) AddRef();
        return *output ? S_OK : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    HRESULT STDMETHODCALLTYPE GetBuffer(RPCOLEMESSAGE* message, REFIID) override
    {
        message->Buffer = CoTaskMemAlloc(message->cbBuffer);
        return message->Buffer ? S_OK : E_OUTOFMEMORY;
    }
    HRESULT STDMETHODCALLTYPE SendReceive(RPCOLEMESSAGE*, ULONG* status) override
    {
        ++requests;
        if (status) *status = 0;
        return E_ACCESSDENIED;
    }
    HRESULT STDMETHODCALLTYPE FreeBuffer(RPCOLEMESSAGE* message) override
    {
        CoTaskMemFree(message->Buffer);
        message->Buffer = nullptr;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetDestCtx(DWORD* context, void** value) override
    {
        *context = MSHCTX_LOCAL;
        *value = nullptr;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE IsConnected() override { return S_OK; }
private:
    ULONG references_ = 1;
};

int TargetMain(int, wchar_t**)
{
    Require(SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED)), "Initialize COM proxy workload");
    ProxyChannel channel;
    {
        // System proxies share generic entries while their interface contracts require different native stacks.
        CLSID identity{};
        ComPtr<IPSFactoryBuffer> factory;
        Require(CoGetPSClsid(__uuidof(IVirtualDesktopManager), &identity) == S_OK &&
            CoGetClassObject(identity, CLSCTX_INPROC_SERVER, nullptr, IID_PPV_ARGS(&factory)) == S_OK,
            "Create system proxy factory");
        ComPtr<IRpcProxyBuffer> desktopControl, itemControl;
        ComPtr<IVirtualDesktopManager> desktop;
        ComPtr<IShellItem> item;
        Require(factory->CreateProxy(nullptr, __uuidof(IVirtualDesktopManager), &desktopControl,
            reinterpret_cast<void**>(desktop.GetAddressOf())) == S_OK &&
            factory->CreateProxy(nullptr, IID_IShellItem, &itemControl,
                reinterpret_cast<void**>(item.GetAddressOf())) == S_OK,
            "Create standard COM proxies");
        auto firstTable = *reinterpret_cast<void***>(desktop.Get());
        auto secondTable = *reinterpret_cast<void***>(item.Get());
        std::printf("tables=%p/%p slot3=%p/%p\n", firstTable, secondTable, firstTable[3], secondTable[3]);
        Require(firstTable == secondTable, "System proxies do not share their runtime vtable");
        Require(desktopControl->Connect(&channel) == S_OK && itemControl->Connect(&channel) == S_OK,
            "Connect local COM proxy channel");

        // The second call passes an output pointer beyond the register arguments and reaches a failing channel.
        BOOL returned = TRUE;
        IUnknown* handler = reinterpret_cast<IUnknown*>(uintptr_t{1});
        auto first = desktop->IsWindowOnCurrentVirtualDesktop(nullptr, &returned);
        auto second = item->BindToHandler(nullptr, GUID_NULL, IID_IUnknown, reinterpret_cast<void**>(&handler));
        desktopControl->Disconnect();
        itemControl->Disconnect();
        std::printf("results=%08lX/%08lX requests=%lu handler=%p\n", first, second, channel.requests, handler);
        Require(first == E_ACCESSDENIED && second == E_ACCESSDENIED && !handler && channel.requests == 2,
            "Shared COM proxy methods changed their arguments or channel result");
    }
    CoUninitialize();
    std::puts("PASS: shared COM proxy calls retain their native argument layouts.");
    return 0;
}

void SharedProxies(const Context& context)
{
    Require(RunTarget(context).contains("PASS:"), "Shared COM proxy baseline failed");
    Capture::Run(context, {.instructions = false, .comOnly = true}, [&](Capture& capture)
    {
        Require(!Named(capture.Calls(), "IUnknown::QueryInterface").empty(),
            "Shared COM proxy capture lost interface discovery");
        auto requests = Named(capture.Calls(), "IRpcChannelBuffer::SendReceive");
        Require(requests.size() == 2 && std::ranges::all_of(requests, [](const Json& call)
        {
            return call["result"] == static_cast<uint32_t>(E_ACCESSDENIED);
        }), "Shared COM proxy calls did not reach their local channel", requests);
        capture.CheckDiagnostics();
    });
}

int wmain(int argc, wchar_t** argv)
{
    try { return Run<TargetMain>(argc, argv, SharedProxies); }
    catch (const std::exception& error)
    {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
