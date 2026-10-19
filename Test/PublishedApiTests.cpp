#include "TestSupport.h"
#include "Protocol.h"
#include <uianimation.h>
#include <wincodec.h>
#include <portabledevicetypes.h>
#include <d3d12.h>
#include <presentation.h>
#include <ks.h>
#include <ksproxy.h>
#include <xamlom.h>

using namespace Detourist::Tests;
using Microsoft::WRL::ComPtr;

extern "C" BOOL ExerciseDirectSoundProperties();

class CaptureAbi final : public IClassFactory, public IIndependentFlipFramePresentStatistics,
    public ID3D12StateObjectProperties1, public IVisualTreeServiceCallback, public IKsPropertySet
{
public:
    __declspec(noinline) HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid == IID_IUnknown || iid == IID_IClassFactory) *output = static_cast<IClassFactory*>(this);
        else if (iid == __uuidof(IIndependentFlipFramePresentStatistics))
            *output = static_cast<IIndependentFlipFramePresentStatistics*>(this);
        else if (iid == __uuidof(ID3D12StateObjectProperties1))
            *output = static_cast<ID3D12StateObjectProperties1*>(this);
        else if (iid == __uuidof(IVisualTreeServiceCallback)) *output = static_cast<IVisualTreeServiceCallback*>(this);
        else if (iid == __uuidof(IKsPropertySet)) *output = static_cast<IKsPropertySet*>(this);
        if (!*output) return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** output) override
    {
        return outer ? CLASS_E_NOAGGREGATION : QueryInterface(iid, output);
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL) override { return S_OK; }
    UINT64 STDMETHODCALLTYPE GetPresentId() override { return 41; }
    PresentStatisticsKind STDMETHODCALLTYPE GetKind() override { return static_cast<PresentStatisticsKind>(0); }
    __declspec(noinline) LUID STDMETHODCALLTYPE GetOutputAdapterLUID() override { return {0x12345678, -0x1234}; }
    UINT STDMETHODCALLTYPE GetOutputVidPnSourceId() override { return 7; }
    UINT_PTR STDMETHODCALLTYPE GetContentTag() override { return 9; }
    __declspec(noinline) SystemInterruptTime STDMETHODCALLTYPE GetDisplayedTime() override
    {
        return {0x0123456789ABCDEF};
    }
    __declspec(noinline) SystemInterruptTime STDMETHODCALLTYPE GetPresentDuration() override
    {
        return {0x76543210FEDCBA98};
    }
    void* STDMETHODCALLTYPE GetShaderIdentifier(LPCWSTR) override { return nullptr; }
    UINT64 STDMETHODCALLTYPE GetShaderStackSize(LPCWSTR) override { return 0; }
    UINT64 STDMETHODCALLTYPE GetPipelineStackSize() override { return 0; }
    void STDMETHODCALLTYPE SetPipelineStackSize(UINT64) override {}
    __declspec(noinline) D3D12_PROGRAM_IDENTIFIER STDMETHODCALLTYPE GetProgramIdentifier(LPCWSTR name) override
    {
        return name && !wcscmp(name, L"ABI record") ? D3D12_PROGRAM_IDENTIFIER{{11, 22, 33, 44}} :
            D3D12_PROGRAM_IDENTIFIER{};
    }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE OnVisualTreeChange(ParentChildRelation relation,
        VisualElement element, VisualMutationType mutation) override
    {
        return relation.Parent == 0x0123456789ABCDEF && relation.ChildIndex == 0x12345 &&
            element.Handle == 0x76543210FEDCBA98 && element.NumChildren == 7 &&
            mutation == static_cast<VisualMutationType>(1) ? S_OK : E_INVALIDARG;
    }
    HRESULT STDMETHODCALLTYPE Set(REFGUID, ULONG, void*, ULONG, void* data, ULONG length) override
    {
        if (!data || length != sizeof(property_)) return E_INVALIDARG;
        property_ = *static_cast<DWORD*>(data);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Get(REFGUID, ULONG, void*, ULONG, void* data, ULONG length, ULONG* written) override
    {
        if (!data || length != sizeof(property_) || !written) return E_INVALIDARG;
        *static_cast<DWORD*>(data) = property_;
        *written = sizeof(property_);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE QuerySupported(REFGUID, ULONG, ULONG*) override { return E_NOTIMPL; }

private:
    ULONG references_ = 1;
    ULONG property_ = 0;
};

int TargetMain(int, wchar_t**)
{
    Require(SUCCEEDED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)), "Initialize published API workload");
    {
        // A factory's floating argument and returned interface exercise the complete animation call path.
        ComPtr<IUIAnimationManager> manager;
        ComPtr<IUIAnimationVariable> variable;
        double value = 0;
        Require(CoCreateInstance(__uuidof(UIAnimationManager), nullptr, CLSCTX_INPROC_SERVER,
                    IID_PPV_ARGS(&manager)) == S_OK &&
                manager->CreateAnimationVariable(0.375, &variable) == S_OK &&
                variable->GetValue(&value) == S_OK && value == 0.375,
            "Preserve animation factory arguments and output");

        // The in-memory property bag exposes a string typedef without a separate termination annotation.
        ComPtr<IPortableDeviceValues> properties;
        LPWSTR returned = nullptr;
        Require(CoCreateInstance(__uuidof(PortableDeviceValues), nullptr, CLSCTX_INPROC_SERVER,
                    IID_PPV_ARGS(&properties)) == S_OK &&
                properties->SetStringValue(PKEY_Comment, L"catalog string") == S_OK &&
                properties->GetStringValue(PKEY_Comment, &returned) == S_OK,
            "Create a string property");
        const auto matches = returned && wcscmp(returned, L"catalog string") == 0;
        CoTaskMemFree(returned);
        Require(matches, "Preserve the string property value");

        // The documented imaging proxy must retain both scalar output buffers.
        ComPtr<IWICImagingFactory> imaging;
        ComPtr<IWICBitmap> bitmap;
        Require(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                    IID_PPV_ARGS(&imaging)) == S_OK &&
                imaging->CreateBitmap(11, 7, GUID_WICPixelFormat32bppBGRA, WICBitmapCacheOnLoad, &bitmap) == S_OK,
            "Create imaging proxy workload");
        auto module = GetModuleHandleW(L"windowscodecs.dll");
        using GetSize = HRESULT(WINAPI*)(IWICBitmapSource*, UINT*, UINT*);
        auto getSize = reinterpret_cast<GetSize>(GetProcAddress(module, "IWICBitmapSource_GetSize_Proxy"));
        UINT width = 0, height = 0;
        Require(getSize && getSize(bitmap.Get(), &width, &height) == S_OK && width == 11 && height == 7,
            "Preserve documented imaging proxy outputs");
        using CreateColorContext = HRESULT(WINAPI*)(IWICImagingFactory*, IWICColorContext**);
        auto createColor = reinterpret_cast<CreateColorContext>(GetProcAddress(module, "WICCreateColorContext_Proxy"));
        ComPtr<IWICColorContext> color;
        Require(createColor && createColor(imaging.Get(), color.GetAddressOf()) == S_OK && color,
            "Preserve the imaging proxy interface output");

        // An actual native export exercises its x86 stack contract and counted output buffer.
        using ProcessPrng = BOOL(WINAPI*)(PBYTE, SIZE_T);
        auto randomModule = GetModuleHandleW(L"bcryptprimitives.dll");
        auto random = reinterpret_cast<ProcessPrng>(GetProcAddress(randomModule, "ProcessPrng"));
        BYTE randomBytes[37]{};
        Require(random && random(randomBytes, sizeof(randomBytes)), "Call the native random-number provider");

        // Public COM contracts exercise returned records and two large by-value arguments without hardware.
        CaptureAbi fixture;
        constexpr CLSID classId{0x3AA70B11, 0xE49C, 0x4DBC, {0x9F, 0x71, 0x2B, 0x17, 0x18, 0x21, 0x10, 0x52}};
        DWORD registration = 0;
        Require(CoRegisterClassObject(classId, static_cast<IClassFactory*>(&fixture), CLSCTX_INPROC_SERVER,
                    REGCLS_MULTIPLEUSE, &registration) == S_OK, "Register ABI fixture");
        {
            ComPtr<IIndependentFlipFramePresentStatistics> statistics;
            ComPtr<ID3D12StateObjectProperties1> program;
            ComPtr<IVisualTreeServiceCallback> visual;
            ComPtr<IKsPropertySet> propertySet;
            Require(CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&statistics)) == S_OK &&
                    CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&program)) == S_OK &&
                    CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&visual)) == S_OK &&
                    CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&propertySet)) == S_OK,
                "Create ABI fixtures");
            auto luid = statistics->GetOutputAdapterLUID();
            auto displayed = statistics->GetDisplayedTime();
            auto duration = statistics->GetPresentDuration();
            auto identifier = program->GetProgramIdentifier(L"ABI record");
            ParentChildRelation relation{};
            relation.Parent = 0x0123456789ABCDEF;
            relation.ChildIndex = 0x12345;
            VisualElement element{};
            element.Handle = 0x76543210FEDCBA98;
            element.NumChildren = 7;
            Require(luid.LowPart == 0x12345678 && luid.HighPart == -0x1234 &&
                    displayed.value == 0x0123456789ABCDEF && duration.value == 0x76543210FEDCBA98 &&
                    identifier.OpaqueData[0] == 11 && identifier.OpaqueData[3] == 44 &&
                    visual->OnVisualTreeChange(relation, element, static_cast<VisualMutationType>(1)) == S_OK,
                "Preserve record arguments and returns");

            // The KSProxy contract shares the IID with DirectSound but declares different Get and Set slots.
            ULONG propertyValue = 12345, propertyResult = 0, written = 0;
            Require(propertySet->Set(GUID_NULL, 0, nullptr, 0, &propertyValue, sizeof(propertyValue)) == S_OK &&
                    propertySet->Get(GUID_NULL, 0, nullptr, 0, &propertyResult, sizeof(propertyResult), &written) ==
                        S_OK && propertyResult == propertyValue && written == sizeof(propertyResult),
                "Preserve the property set call contract");
        }
        Require(CoRevokeClassObject(registration) == S_OK, "Revoke ABI fixture");
        Require(ExerciseDirectSoundProperties(), "Call the system DirectSound property methods");
    }
    CoUninitialize();
    std::puts("PASS: published APIs preserve floating arguments and output buffers.");
    return 0;
}

void PublishedApis(const Context& context)
{
    Require(RunTarget(context).contains("PASS:"), "Published API baseline failed");
    const auto instructions = context.Has(L"--instructions");
    Capture::Run(context, {.limit = 64, .instructions = instructions}, [&](Capture& capture)
    {
        // Interface discovery must carry the factory result into its newly cataloged methods.
        auto calls = capture.Calls();
        auto create = Only(Named(calls, "IUIAnimationManager::CreateAnimationVariable"));
        Require(create["argument_count"] == 3 && Read<double>(create["arguments"], 8) == 0.375,
            "Animation factory floating argument differs", create);
        auto value = Only(Named(calls, "IUIAnimationVariable::GetValue"));
        auto output = Only(Regions(value["output"], {.parameter = 1}));
        Require(value["result"] == S_OK && output.data.size() == sizeof(double) &&
                Read<double>(output.data) == 0.375,
            "Animation variable output differs", value);
        auto property = Only(Named(calls, "IPortableDeviceValues::SetStringValue"));
        auto text = Only(Regions(property["input"], {.parameter = 2}));
        constexpr wchar_t expected[] = L"catalog string";
        Require(text.data.size() >= sizeof(expected) - sizeof(wchar_t) &&
                memcmp(text.data.data(), expected, sizeof(expected) - sizeof(wchar_t)) == 0,
            "String typedef input was truncated", property);
        auto getProperty = Only(Named(calls, "IPortableDeviceValues::GetStringValue"));
        auto returnedText = Only(Regions(getProperty["output"],
            {.parameter = 2, .kind = 1, .required = Detourist::ReferencedData}));
        Require(returnedText.data.size() == sizeof(expected) &&
                !memcmp(returnedText.data.data(), expected, sizeof(expected)),
            "Allocated string output was not resolved", getProperty);
        auto random = Select(Named(calls, "ProcessPrng"), [](const auto& call)
        {
            return call["argument_count"] == 2 && Read<uint64_t>(call["arguments"], 8) == 37;
        });
        auto randomCall = Only(random);
        auto randomOutput = Only(Regions(randomCall["output"], {.parameter = 0}));
        Require(randomCall["result"] != 0 && randomOutput.data.size() == 37,
            "Native counted output was truncated", randomCall);

        // The captured structure contains the caller's return buffer, while arguments remain in their own slots.
        auto luid = Only(Named(calls, "IIndependentFlipFramePresentStatistics::GetOutputAdapterLUID"));
        auto luidValue = Only(Regions(luid["output"], {.parameter = UINT32_MAX}));
        auto luidRecord = Read<LUID>(luidValue.data);
        Require(luid["argument_count"] == 1 && luidRecord.LowPart == 0x12345678 && luidRecord.HighPart == -0x1234,
            "Small record return differs", luid);
        auto identifier = Only(Named(calls, "ID3D12StateObjectProperties1::GetProgramIdentifier"));
        auto identifierValue = Only(Regions(identifier["output"], {.parameter = UINT32_MAX}));
        auto identifierRecord = Read<D3D12_PROGRAM_IDENTIFIER>(identifierValue.data);
        Require(identifier["argument_count"] == 2 && identifierRecord.OpaqueData[0] == 11 &&
                identifierRecord.OpaqueData[3] == 44 && !Regions(identifier["input"], {.parameter = 1}).empty(),
            "Record return shifted a declared argument", identifier);
        auto visual = Only(Named(calls, "IVisualTreeServiceCallback::OnVisualTreeChange"));
        auto relation = Read<ParentChildRelation>(Only(Regions(visual["input"], {.parameter = 1})).data);
        auto element = Read<VisualElement>(Only(Regions(visual["input"], {.parameter = 2})).data);
        Require(visual["argument_count"] == 4 && visual["result"] == S_OK &&
                relation.Parent == 0x0123456789ABCDEF && relation.ChildIndex == 0x12345 &&
                element.Handle == 0x76543210FEDCBA98 && element.NumChildren == 7 &&
                Read<uint64_t>(visual["arguments"], 24) == 1,
            "Large by-value arguments or following scalar differ", visual);

        auto get = Only(Named(calls, "IKsPropertySet::Get"));
        auto set = Only(Named(calls, "IKsPropertySet::Set"));
        auto support = Only(Named(calls, "IKsPropertySet::QuerySupport"));
        Require(get["argument_count"] == 8 && Read<uint64_t>(get["arguments"], 16) == 73 &&
                set["argument_count"] == 7 && Read<uint64_t>(set["arguments"], 16) == 74 &&
                support["argument_count"] == 4 && support["result"] == S_OK,
            "Only the system DirectSound provider should receive its typed property signatures");
        if (instructions)
        {
            for (auto name : {"{31efac30-515c-11d0-a9aa-00aa0061be93}::slot 3",
                "{31efac30-515c-11d0-a9aa-00aa0061be93}::slot 4"})
            {
                auto call = Only(Named(calls, name));
                Require(call["flags"].get<uint32_t>() & Detourist::RawArguments,
                    "Ambiguous property-set method did not retain raw capture", call);
            }

            // Shared proxy entries have incompatible signatures; the resolved COM method owns typed outputs.
            auto size = Only(Named(calls, "IWICBitmap::GetSize"));
            auto width = Only(Regions(size["output"], {.parameter = 1}));
            auto height = Only(Regions(size["output"], {.parameter = 2}));
            Require(size["argument_count"] == 3 && size["result"] == S_OK &&
                    width.data.size() == sizeof(UINT) && height.data.size() == sizeof(UINT) &&
                    Read<UINT>(width.data) == 11 && Read<UINT>(height.data) == 7,
                "Imaging proxy output buffers differ", size);
        }
        capture.CheckDiagnostics();
    });
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, PublishedApis); }
