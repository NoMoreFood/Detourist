#include "TestSupport.h"

using namespace Detourist::Tests;
template<UINT Identity> class RpcLeaf final : public CountedUnknown<IDispatch>
{
public:
    ULONG queries = 0;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void** value) override
    {
        ++queries;
        if (value) *value = nullptr;
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT* count) override
    {
        if (!count) return E_POINTER;
        *count = 0;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID, LPOLESTR*, UINT, LCID, DISPID* output) override
    {
        if (!output) return E_POINTER;
        *output = Identity;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*) override
    {
        return E_NOTIMPL;
    }
};


class RpcBag final : public CountedUnknown<IPropertyBag2>
{
public:
    std::array<IDispatch*, 3> leaves;
    ULONG queries = 0, callbacks = 0;
    bool fail = false;
    explicit RpcBag(std::array<IDispatch*, 3> values) : leaves(values) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        ++queries;
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IPropertyBag2) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Read(ULONG count, PROPBAG2*, IErrorLog*, VARIANT* values, HRESULT* errors) override
    {
        if (count > leaves.size() || count && (!values || !errors)) return E_INVALIDARG;
        for (ULONG index = 0; index < count; ++index)
        {
            values[index] = {};
            values[index].vt = VT_DISPATCH;
            values[index].pdispVal = leaves[index];
            errors[index] = S_OK;
        }
        return fail ? E_FAIL : S_OK;
    }
    HRESULT STDMETHODCALLTYPE Write(ULONG count, PROPBAG2*, VARIANT* values) override
    {
        if (count > leaves.size() || count && !values) return E_INVALIDARG;
        for (ULONG index = 0; index < count; ++index)
        {
            if (values[index].vt != VT_DISPATCH || !values[index].pdispVal) return E_INVALIDARG;
            UINT types = 99;
            ++callbacks;
            if (values[index].pdispVal->GetTypeInfoCount(&types) != S_OK || types) return E_FAIL;
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CountProperties(ULONG* count) override { *count = 3; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetPropertyInfo(ULONG, ULONG, PROPBAG2*, ULONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE LoadObject(LPCOLESTR, DWORD, IUnknown*, IErrorLog*) override { return E_NOTIMPL; }
};

class RpcEnumerator final : public CountedUnknown<IEnumUnknown>
{
public:
    std::array<IUnknown*, 3> leaves;
    ULONG queries = 0, completed = 3;
    bool fail = false;
    explicit RpcEnumerator(std::array<IUnknown*, 3> values) : leaves(values) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        ++queries;
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IEnumUnknown) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Next(ULONG capacity, IUnknown** values, ULONG* fetched) override
    {
        if (!values || (!fetched && capacity != 1)) return E_POINTER;
        auto count = std::min(capacity, completed);
        for (ULONG index = 0; index < count; ++index) values[index] = leaves[index];
        if (fetched) *fetched = count;
        return fail ? E_FAIL : count == capacity ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Reset() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumUnknown**) override { return E_NOTIMPL; }
};

class MonikerEnumerator final : public CountedUnknown<IEnumMoniker>
{
public:
    IMoniker* item;
    bool empty;
    MonikerEnumerator(IMoniker* value, bool noItems) : item(value), empty(noItems) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IEnumMoniker) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Next(ULONG capacity, IMoniker** values, ULONG* fetched) override
    {
        if (!values || (!fetched && capacity != 1)) return E_POINTER;
        if (fetched) *fetched = 0;
        if (empty || !capacity) return S_FALSE;
        *values = item;
        item->AddRef();
        if (fetched) *fetched = 1;
        return capacity == 1 ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Reset() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumMoniker**) override { return E_NOTIMPL; }
};

class StringEnumerator final : public CountedUnknown<IEnumString>
{
public:
    bool empty;
    explicit StringEnumerator(bool noItems) : empty(noItems) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IEnumString) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Next(ULONG capacity, LPOLESTR* values, ULONG* fetched) override
    {
        if (!values || (!fetched && capacity != 1)) return E_POINTER;
        if (fetched) *fetched = 0;
        if (empty || !capacity) return S_FALSE;
        auto value = static_cast<LPOLESTR>(CoTaskMemAlloc(sizeof(L"Detourist")));
        if (!value) return E_OUTOFMEMORY;
        lstrcpyW(value, L"Detourist");
        *values = value;
        if (fetched) *fetched = 1;
        return capacity == 1 ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Reset() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumString**) override { return E_NOTIMPL; }
};

class FormatEnumerator final : public CountedUnknown<IEnumFORMATETC>
{
public:
    bool empty;
    explicit FormatEnumerator(bool noItems) : empty(noItems) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IEnumFORMATETC) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Next(ULONG capacity, FORMATETC* values, ULONG* fetched) override
    {
        if (!values || (!fetched && capacity != 1)) return E_POINTER;
        if (fetched) *fetched = 0;
        if (empty || !capacity) return S_FALSE;
        *values = {CF_UNICODETEXT, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
        if (fetched) *fetched = 1;
        return capacity == 1 ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Reset() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumFORMATETC**) override { return E_NOTIMPL; }
};

class ConnectionPointLeaf final : public CountedUnknown<IConnectionPoint>
{
public:
    ULONG queries = 0;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        ++queries;
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IConnectionPoint) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE GetConnectionInterface(IID* iid) override
    {
        if (!iid) return E_POINTER;
        *iid = IID_IDispatch;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetConnectionPointContainer(IConnectionPointContainer**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Advise(IUnknown*, DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Unadvise(DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE EnumConnections(IEnumConnections**) override { return E_NOTIMPL; }
};

class ConnectionPointEnumerator final : public CountedUnknown<IEnumConnectionPoints>
{
public:
    IConnectionPoint* point;
    bool empty;
    ConnectionPointEnumerator(IConnectionPoint* value, bool noItems) : point(value), empty(noItems) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IEnumConnectionPoints) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Next(ULONG capacity, IConnectionPoint** values, ULONG* fetched) override
    {
        if (!values || (!fetched && capacity != 1)) return E_POINTER;
        if (fetched) *fetched = 0;
        if (empty || !capacity) return S_FALSE;
        *values = point;
        point->AddRef();
        if (fetched) *fetched = 1;
        return capacity == 1 ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Reset() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumConnectionPoints**) override { return E_NOTIMPL; }
};

template<ULONG Identity> class RpcCondition final : public CountedUnknown<IUIAutomationCondition>
{
public:
    ULONG queries = 0;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void** value) override
    {
        queries += Identity;
        if (value) *value = nullptr;
        return E_NOINTERFACE;
    }
};

class RpcConditions final : public CountedUnknown<IUIAutomationOrCondition>
{
public:
    std::array<IUIAutomationCondition*, 3> children;
    bool fail = false, empty = false;
    explicit RpcConditions(std::array<IUIAutomationCondition*, 3> values) : children(values) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IUIAutomationOrCondition) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE get_ChildCount(int* count) override { *count = empty ? 0 : 3; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetChildrenAsNativeArray(IUIAutomationCondition*** values, int* count) override
    {
        if (!values || !count) return E_POINTER;
        *values = empty ? nullptr : children.data();
        *count = empty ? 0 : 3;
        return fail ? E_FAIL : S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetChildren(SAFEARRAY**) override { return E_NOTIMPL; }
};

class RpcPipe final : public CountedUnknown<IPipeByte>
{
public:
    bool fail = false, empty = false;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IPipeByte) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Pull(BYTE* values, ULONG capacity, ULONG* returned) override
    {
        if (!values || !returned) return E_POINTER;
        *returned = empty ? 0 : std::min<ULONG>(capacity, 48);
        for (ULONG index = 0; index < *returned; ++index) values[index] = static_cast<BYTE>(index ^ 0x6D);
        return fail ? E_FAIL : S_OK;
    }
    HRESULT STDMETHODCALLTYPE Push(BYTE* values, ULONG count) override
    {
        for (ULONG index = 0; index < count; ++index)
            if (values[index] != static_cast<BYTE>(index ^ 0x6D)) return E_INVALIDARG;
        return S_OK;
    }
};

__declspec(noinline) HRESULT RpcQuery(IUnknown* source, REFIID iid, void** value)
{
    return source->QueryInterface(iid, value);
}

__declspec(noinline) bool RpcTouch(IDispatch* source)
{
    UINT count = 99;
    return source->GetTypeInfoCount(&count) == S_OK && !count;
}

int TargetMain(int argc, wchar_t** argv)
{
    const auto mode = argc > 1 ? argv[1] : L"output";
    if (!wcsncmp(mode, L"string-", 7))
    {
        // Single-item enumeration may omit the fetched count while preserving the returned string pointer.
        StringEnumerator root(!wcscmp(mode, L"string-empty"));
        void* queried = nullptr;
        bool passed = RpcQuery(&root, __uuidof(IEnumString), &queried) == S_OK;
        auto enumerator = static_cast<IEnumString*>(queried);
        auto output = reinterpret_cast<LPOLESTR>(static_cast<uintptr_t>(0x1234));
        if (passed) passed = enumerator->Next(1, &output, nullptr) == (root.empty ? S_FALSE : S_OK);
        if (passed && !root.empty)
        {
            passed = output && !wcscmp(output, L"Detourist");
            CoTaskMemFree(output);
        }
        else passed &= output == reinterpret_cast<LPOLESTR>(static_cast<uintptr_t>(0x1234));
        if (enumerator) enumerator->Release();
        passed &= root.references == 1;
        printf("mode=%ls leaf_queries=0 references=3\n", mode);
        return passed ? 0 : 2;
    }
    if (!wcsncmp(mode, L"format-", 7))
    {
        // A structure array exercises the catalog extent without an explicit fetched count.
        FormatEnumerator root(!wcscmp(mode, L"format-empty"));
        void* queried = nullptr;
        bool passed = RpcQuery(&root, __uuidof(IEnumFORMATETC), &queried) == S_OK;
        auto enumerator = static_cast<IEnumFORMATETC*>(queried);
        FORMATETC output{};
        output.cfFormat = 0xCDCD;
        if (passed) passed = enumerator->Next(1, &output, nullptr) == (root.empty ? S_FALSE : S_OK);
        passed &= root.empty ? output.cfFormat == 0xCDCD : output.cfFormat == CF_UNICODETEXT &&
            output.dwAspect == DVASPECT_CONTENT && output.lindex == -1 && output.tymed == TYMED_HGLOBAL;
        if (enumerator) enumerator->Release();
        passed &= root.references == 1;
        printf("mode=%ls leaf_queries=0 references=3\n", mode);
        return passed ? 0 : 2;
    }
    if (!wcsncmp(mode, L"connection-", 11))
    {
        // A returned interface is invoked immediately after enumeration without an extra identity query.
        ConnectionPointLeaf point;
        ConnectionPointEnumerator root(&point, !wcscmp(mode, L"connection-empty"));
        void* queried = nullptr;
        bool passed = RpcQuery(&root, __uuidof(IEnumConnectionPoints), &queried) == S_OK;
        auto enumerator = static_cast<IEnumConnectionPoints*>(queried);
        auto output = reinterpret_cast<IConnectionPoint*>(static_cast<uintptr_t>(0x1234));
        if (passed) passed = enumerator->Next(1, &output, nullptr) == (root.empty ? S_FALSE : S_OK);
        if (passed && !root.empty)
        {
            IID iid{};
            passed = output == &point && output->GetConnectionInterface(&iid) == S_OK && iid == IID_IDispatch;
            output->Release();
        }
        else passed &= output == reinterpret_cast<IConnectionPoint*>(static_cast<uintptr_t>(0x1234));
        if (enumerator) enumerator->Release();
        passed &= root.references == 1 && point.references == 1 && !point.queries;
        printf("mode=%ls leaf_queries=%lu references=3\n", mode, point.queries);
        return passed ? 0 : 2;
    }
    if (!wcsncmp(mode, L"moniker-", 8))
    {
        // A real moniker validates the returned interface's method contract after enumeration.
        IMoniker* item = nullptr;
        if (FAILED(CreateItemMoniker(L"!", L"Detourist", &item))) return 2;
        MonikerEnumerator root(item, !wcscmp(mode, L"moniker-empty"));
        void* queried = nullptr;
        bool passed = RpcQuery(&root, __uuidof(IEnumMoniker), &queried) == S_OK;
        auto enumerator = static_cast<IEnumMoniker*>(queried);
        auto output = reinterpret_cast<IMoniker*>(static_cast<uintptr_t>(0x1234));
        if (passed) passed = enumerator->Next(1, &output, nullptr) == (root.empty ? S_FALSE : S_OK);
        if (passed && !root.empty)
        {
            DWORD type = 0;
            passed = output == item && output->IsSystemMoniker(&type) == S_OK && type == MKSYS_ITEMMONIKER;
            output->Release();
        }
        else passed &= output == reinterpret_cast<IMoniker*>(static_cast<uintptr_t>(0x1234));
        if (enumerator) enumerator->Release();
        passed &= root.references == 1;
        item->Release();
        printf("mode=%ls leaf_queries=0 references=3\n", mode);
        return passed ? 0 : 2;
    }
    if (!wcscmp(mode, L"names"))
    {
        // SDK-created type information supplies a real partially filled BSTR output array.
        ICreateTypeLib2* library = nullptr;
        if (CreateTypeLib2(SYS_WIN64, L"Detourist-RpcFixture.tlb", &library) != S_OK) return 2;
        ICreateTypeInfo* information = nullptr;
        OLECHAR typeName[] = L"RpcInfo";
        bool passed = library->CreateTypeInfo(typeName, TKIND_DISPATCH, &information) == S_OK;
        ELEMDESC parameter{};
        parameter.tdesc.vt = VT_I4;
        parameter.paramdesc.wParamFlags = PARAMFLAG_FIN;
        FUNCDESC method{};
        method.memid = 1;
        method.funckind = FUNC_DISPATCH;
        method.invkind = INVOKE_FUNC;
        method.callconv = CC_STDCALL;
        method.cParams = 1;
        method.lprgelemdescParam = &parameter;
        method.elemdescFunc.tdesc.vt = VT_I4;
        OLECHAR* labels[]{const_cast<OLECHAR*>(L"Transform"), const_cast<OLECHAR*>(L"Argument")};
        if (passed) passed = information->AddFuncDesc(0, &method) == S_OK &&
            information->SetFuncAndParamNames(0, labels, static_cast<UINT>(std::size(labels))) == S_OK &&
            information->LayOut() == S_OK;
        void* queried = nullptr;
        if (passed) passed = RpcQuery(information, __uuidof(ITypeInfo), &queried) == S_OK;
        auto source = static_cast<ITypeInfo*>(queried);
        std::array<BSTR, 8> names{};
        UINT count = 0;
        if (passed) passed = source->GetNames(1, names.data(), static_cast<UINT>(names.size()), &count) == S_OK &&
            count == 2 && !wcscmp(names[0], L"Transform") && !wcscmp(names[1], L"Argument");
        for (auto name : names) if (name) SysFreeString(name);
        if (source) source->Release();
        if (information) information->Release();
        library->Release();
        printf("mode=%ls leaf_queries=0 references=3\n", mode);
        return passed ? 0 : 2;
    }
    if (!wcsncmp(mode, L"allocated", 9))
    {
        RpcCondition<1> first;
        RpcCondition<2> second;
        RpcCondition<3> third;
        RpcCondition<99> control;
        RpcConditions root({&first, &second, &third});
        root.empty = !wcscmp(mode, L"allocated-zero");
        root.fail = !wcscmp(mode, L"allocated-failed");
        void* queried = nullptr;
        bool passed = RpcQuery(&root, __uuidof(IUIAutomationOrCondition), &queried) == S_OK;
        auto condition = static_cast<IUIAutomationOrCondition*>(queried);
        IUIAutomationCondition** objects = nullptr;
        int count = 0;
        if (passed) passed = condition->GetChildrenAsNativeArray(&objects, &count) == (root.fail ? E_FAIL : S_OK) &&
            count == (root.empty ? 0 : 3);
        for (int index = 0; index < count; ++index)
            passed &= objects[index]->AddRef() == 2 && objects[index]->Release() == 1;
        passed &= control.AddRef() == 2 && control.Release() == 1;
        if (condition) condition->Release();
        passed &= root.references == 1 && !first.queries && !second.queries && !third.queries && !control.queries &&
            first.references == 1 && second.references == 1 && third.references == 1;
        printf("mode=%ls leaf_queries=%lu references=%lu\n", mode,
            first.queries + second.queries + third.queries, first.references + second.references + third.references);
        return passed ? 0 : 2;
    }
    if (!wcsncmp(mode, L"pipe-", 5))
    {
        RpcPipe root;
        root.empty = !wcscmp(mode, L"pipe-zero");
        root.fail = !wcscmp(mode, L"pipe-failed");
        void* queried = nullptr;
        bool passed = RpcQuery(&root, __uuidof(IPipeByte), &queried) == S_OK;
        auto pipe = static_cast<IPipeByte*>(queried);
        std::array<BYTE, 256> buffer;
        buffer.fill(0xCD);
        ULONG returned = 0;
        if (!wcscmp(mode, L"pipe-input"))
        {
            for (ULONG index = 0; index < 80; ++index) buffer[index] = static_cast<BYTE>(index ^ 0x6D);
            if (passed) passed = pipe->Push(buffer.data(), 80) == S_OK;
        }
        else if (passed)
        {
            passed = pipe->Pull(buffer.data(), static_cast<ULONG>(buffer.size()), &returned) ==
                (root.fail ? E_FAIL : S_OK) && returned == (root.empty ? 0 : 48);
            for (ULONG index = 0; index < buffer.size(); ++index)
                passed &= buffer[index] == (index < returned ? static_cast<BYTE>(index ^ 0x6D) : 0xCD);
        }
        if (pipe) pipe->Release();
        printf("mode=%ls leaf_queries=0 references=3\n", mode);
        return passed && root.references == 1 ? 0 : 2;
    }

    // These producers are queried; returned private interfaces have no RTTI or additional query boundary.
    RpcLeaf<1> first;
    RpcLeaf<2> second;
    RpcLeaf<3> third;
    RpcLeaf<99> control;
    bool passed = true;
    if (!wcsncmp(mode, L"enum-", 5))
    {
        RpcEnumerator root({&first, &second, &third});
        const bool single = !wcscmp(mode, L"enum-single") || !wcscmp(mode, L"enum-single-empty");
        root.completed = !wcscmp(mode, L"enum-zero") || !wcscmp(mode, L"enum-single-empty") ? 0 : 3;
        root.fail = !wcscmp(mode, L"enum-failed");
        void* queried = nullptr;
        passed = RpcQuery(&root, __uuidof(IEnumUnknown), &queried) == S_OK;
        auto enumerator = static_cast<IEnumUnknown*>(queried);
        std::array<IUnknown*, 8> objects;
        objects.fill(&control);
        ULONG count = 99;
        if (passed)
        {
            auto result = enumerator->Next(single ? 1 : 8, objects.data(), single ? nullptr : &count);
            if (single) count = result == S_OK ? 1 : 0;
            passed = result == (root.fail ? E_FAIL : single && root.completed ? S_OK : S_FALSE) &&
                count == (single ? std::min<ULONG>(root.completed, 1) : root.completed);
        }
        for (ULONG index = 0; index < count && index < objects.size(); ++index)
            passed &= objects[index]->AddRef() == 2 && objects[index]->Release() == 1;
        if (enumerator) enumerator->Release();
        passed &= root.queries == 1 && root.references == 1;
    }
    else
    {
        RpcBag root({&first, &second, &third});
        root.fail = !wcscmp(mode, L"failed");
        void* queried = nullptr;
        passed = RpcQuery(&root, __uuidof(IPropertyBag2), &queried) == S_OK;
        auto bag = static_cast<IPropertyBag2*>(queried);
        std::array<PROPBAG2, 3> properties{};
        std::array<VARIANT, 3> values{};
        std::array<HRESULT, 3> errors{E_UNEXPECTED, E_UNEXPECTED, E_UNEXPECTED};
        ULONG count = !wcscmp(mode, L"empty") ? 0 : 3;
        for (ULONG index = 0; index < count; ++index)
        {
            properties[index].dwHint = index + 1;
            properties[index].vt = VT_DISPATCH;
            values[index].vt = VT_DISPATCH;
            values[index].pdispVal = root.leaves[index];
        }
        if (passed && !wcscmp(mode, L"input"))
            passed = bag->Write(count, properties.data(), values.data()) == S_OK && root.callbacks == count;
        else if (passed)
        {
            passed = bag->Read(count, properties.data(), nullptr, values.data(), errors.data()) ==
                (root.fail ? E_FAIL : S_OK);
            for (ULONG index = 0; index < count; ++index) passed &= errors[index] == S_OK;
            passed &= RpcTouch(&first) && RpcTouch(&second) && RpcTouch(&third);
        }
        if (bag) bag->Release();
        passed &= root.queries == 1 && root.references == 1;
    }
    passed &= RpcTouch(&control) && first.queries == 0 && second.queries == 0 && third.queries == 0 &&
        control.queries == 0 && first.references == 1 && second.references == 1 && third.references == 1;
    printf("mode=%ls leaf_queries=%lu references=%lu\n", mode,
        first.queries + second.queries + third.queries, first.references + second.references + third.references);
    return passed ? 0 : 2;
}

void ComRpc(const Context& context)
{
    // Exercise every producer without capture before checking discovery, bounds, and completion counts.
    Json audit = Json::array(), details = Json::array();
    bool baseline = context.Has(L"--baseline");
    for (std::string mode : {"output",
                             "input",
                             "failed",
                             "empty",
                             "enum-partial",
                             "enum-zero",
                             "enum-failed",
                             "enum-single",
                             "enum-single-empty",
                             "moniker-single",
                             "moniker-empty",
                             "string-single",
                             "string-empty",
                             "format-single",
                             "format-empty",
                             "connection-single",
                             "connection-empty",
                             "allocated",
                             "allocated-zero",
                             "allocated-failed",
                             "pipe-output",
                             "pipe-input",
                             "pipe-zero",
                             "pipe-failed",
                             "names"})
    {
        auto arguments = Detourist::Wide(mode);
        Require(RunTarget(context, arguments).contains("leaf_queries=0 references=3"), "COM RPC baseline differs");
        for (uint32_t limit : baseline ? std::vector{16u} : std::vector{16u, 64u})
        {
            Capture::Run(context, {.arguments = arguments, .limit = limit, .comOnly = true}, [&](Capture& capture)
            {
                const auto& rows = capture.Calls();
                auto leaves = Named(rows, "IDispatch::GetTypeInfoCount");
                auto diagnostics = Query(capture.database, "SELECT message FROM diagnostics");
                audit.push_back({{"mode", mode},
                                 {"limit", limit},
                                 {"leafCalls", leaves.size()},
                                 {"diagnostics", diagnostics.size()}});
                if (baseline) return;
                Require(diagnostics.empty() &&
                            Query(capture.database, "SELECT id FROM calls WHERE ended IS NULL").empty(),
                        "COM RPC capture is incomplete", diagnostics);
                Require(leaves.size() == (mode == "output" || mode == "input" ? 3 : 0),
                        "COM RPC discovered leaf count differs", rows);
                auto producerName = mode == "names"             ? "ITypeInfo::GetNames"
                                    : mode == "pipe-input"      ? "IPipeByte::Push"
                                    : mode.starts_with("pipe-") ? "IPipeByte::Pull"
                                    : mode.starts_with("allocated")
                                        ? "IUIAutomationOrCondition::GetChildrenAsNativeArray"
                                    : mode.starts_with("enum-")       ? "IEnumUnknown::Next"
                                    : mode.starts_with("moniker-")    ? "IEnumMoniker::Next"
                                    : mode.starts_with("string-")     ? "IEnumString::Next"
                                    : mode.starts_with("format-")     ? "IEnumFORMATETC::Next"
                                    : mode.starts_with("connection-") ? "IEnumConnectionPoints::Next"
                                    : mode == "input"                 ? "IPropertyBag2::Write"
                                                                      : "IPropertyBag2::Read";
                auto producers = Named(rows, producerName);
                Require(!producers.empty(), "COM RPC producer missing", rows);
                auto producer = producers[0];
                if (mode.starts_with("moniker-") || mode.starts_with("connection-"))
                {
                    auto method = mode.starts_with("moniker-") ? "IMoniker::IsSystemMoniker"
                                                               : "IConnectionPoint::GetConnectionInterface";
                    Require(Named(rows, method).size() == (mode.ends_with("empty") ? 0 : 1),
                            "COM RPC typed enumerator discovery differs", rows);
                }
                else if (mode.starts_with("string-") || mode.starts_with("format-"))
                    Require(producers.size() == 1, "COM RPC enumerator count differs", rows);
                for (const auto& row : rows)
                {
                    auto name = row["name"].get<std::string>();
                    bool specialized = mode.starts_with("moniker-") || mode.starts_with("connection-") ||
                                       mode.starts_with("string-") || mode.starts_with("format-");
                    if (!specialized || name == producerName || name == "IMoniker::IsSystemMoniker" ||
                        name == "IConnectionPoint::GetConnectionInterface")
                        Require(!(row["flags"].get<uint32_t>() & 256), "COM RPC method contract is raw", row);
                    CheckLimit(row, limit);
                }
                bool input = mode == "input" || mode == "pipe-input";
                auto values = Values(producer[input ? "input" : "output"]);
                uint32_t parameter = mode == "names"                                              ? 2
                                     : mode.starts_with("allocated") || mode.starts_with("pipe-") ? 1
                                     : mode.starts_with("enum-") || mode.starts_with("moniker-") ||
                                             mode.starts_with("string-") || mode.starts_with("format-") ||
                                             mode.starts_with("connection-")
                                         ? 2
                                     : mode == "input" ? 3
                                                       : 4;
                auto captured = Regions(values, {.parameter = parameter, .kind = 0});
                if (mode == "failed" || mode.ends_with("-failed"))
                    Require((producer["flags"].get<uint32_t>() & 1) && captured.empty(),
                            "Failed COM RPC output was captured", producer);
                else if (mode == "allocated-zero")
                    Require(captured.empty() && Snapshots(producer["output"], 1, 2) == std::vector<Bytes>{Bytes(8)},
                            "Empty allocated COM RPC output differs", producer);
                else if (mode == "string-empty" || mode == "format-empty" || mode == "pipe-zero")
                {
                    Require(captured.empty(), "Empty COM RPC output was dereferenced", producer);
                    if (mode == "pipe-zero")
                        Require(Snapshots(producer["output"], 3, 2) == std::vector<Bytes>{Bytes(4)},
                                "Empty pipe output count differs", producer);
                }
                else if (mode == "empty" || mode == "enum-zero" || mode.ends_with("-empty"))
                    Require(captured == std::vector<Value>{{parameter, 0, 0, 0, {}}},
                            "Empty COM RPC array metadata differs", producer);
                else
                {
                    uint32_t size = mode == "format-single"                         ? 32
                                    : mode == "names"                               ? 16
                                    : mode.ends_with("-single")                     ? 8
                                    : mode == "enum-partial" || mode == "allocated" ? 24
                                    : mode == "pipe-output"                         ? 48
                                    : mode == "pipe-input"                          ? 80
                                                                                    : 72;
                    Require(captured.size() == 1 && captured[0].original == size &&
                                captured[0].data.size() == std::min(limit, size),
                            "COM RPC array extent differs", producer);
                    if (mode.starts_with("pipe-"))
                    {
                        Bytes expected(std::min(limit, size));
                        for (size_t i = 0; i < expected.size(); ++i)
                            expected[i] = static_cast<uint8_t>(i ^ 0x6d);
                        Require(captured[0].data == expected, "COM RPC pipe bytes differ", producer);
                    }
                }
                if (mode == "names")
                {
                    auto text = Regions(values, {.required = 64});
                    Require(text.size() == 2 && text[0].flags >> 16 == 0 && text[1].flags >> 16 == 1 &&
                                text[0].data == Prefix(Encode("Transform", true), limit / 2 * 2) &&
                                text[1].data == Prefix(Encode("Argument", true), limit / 2 * 2),
                            "COM RPC name array differs", producer);
                }
                if (mode == "output")
                {
                    auto errors = Regions(values, {.parameter = 5});
                    Require(errors.size() == 1 && errors[0].original == 12 && errors[0].data == Bytes(12),
                            "COM RPC per-item errors differ", producer);
                }
                if (mode == "input")
                    for (const auto& row : leaves)
                        Require(producer["started"] <= row["started"] && row["started"] < row["ended"] &&
                                    row["ended"] <= producer["ended"],
                                "COM RPC input discovery is outside the producer", row);
                if (mode.starts_with("enum-") || mode.starts_with("allocated"))
                    Require(Named(rows, "IUnknown::AddRef").size() == (mode == "enum-single" ? 1
                                                                       : mode == "enum-partial" || mode == "allocated"
                                                                           ? 3
                                                                           : 0),
                            "COM RPC reference count differs", rows);
                details.push_back({{"mode", mode}, {"limit", limit}, {"call", capture.Details(producer)}});
            }, 40);
        }
    }
    WriteJson(context.directory / L"audit.json", audit);
    WriteJson(context.directory / L"details.json", details);
    if (!baseline) Inspect(context, context.Option(L"--inspector"), "--com-rpc-arrays", details, 30000);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, ComRpc); }
