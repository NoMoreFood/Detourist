#define COBJMACROS
#include <windows.h>
#include <mmsystem.h>
#include <cguid.h>
#include <initguid.h>
#include <dsound.h>
#include <dsconf.h>

BOOL ExerciseDirectSoundProperties(void)
{
    // Load the real provider through an alternate spelling of its system path.
    WCHAR path[MAX_PATH + 16] = L"\\\\?\\";
    UINT length = GetSystemDirectoryW(path + 4, MAX_PATH);
    if (!length || length >= MAX_PATH || wcscat_s(path, _countof(path), L"\\dsound.dll")) return FALSE;
    HMODULE library = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library) return FALSE;

    // Publish the private class factory so capture observes an ordinary COM activation.
    LPFNGETCLASSOBJECT getFactory = (LPFNGETCLASSOBJECT)GetProcAddress(library, "DllGetClassObject");
    IClassFactory* factory = NULL;
    DWORD cookie = 0;
    BOOL passed = FALSE;
    if (getFactory && SUCCEEDED(getFactory(&CLSID_DirectSoundPrivate, &IID_IClassFactory, (void**)&factory)))
    {
        if (SUCCEEDED(CoRegisterClassObject(&CLSID_DirectSoundPrivate, (IUnknown*)factory, CLSCTX_INPROC_SERVER,
            REGCLS_MULTIPLEUSE, &cookie)))
        {
            LPKSPROPERTYSET properties = NULL;
            if (SUCCEEDED(CoCreateInstance(&CLSID_DirectSoundPrivate, NULL, CLSCTX_INPROC_SERVER,
                &IID_IKsPropertySet, (void**)&properties)))
            {
                ULONG support = 0, bytes = 0;
                passed = IKsPropertySet_QuerySupport(properties, &DSPROPSETID_DirectSoundDevice,
                    DSPROPERTY_DIRECTSOUNDDEVICE_DESCRIPTION_W, &support) == S_OK &&
                    FAILED(IKsPropertySet_Get(properties, &GUID_NULL, 73, NULL, 0, NULL, 0, &bytes)) &&
                    FAILED(IKsPropertySet_Set(properties, &GUID_NULL, 74, NULL, 0, NULL, 0));
                IKsPropertySet_Release(properties);
            }
            CoRevokeClassObject(cookie);
        }
        IClassFactory_Release(factory);
    }
    FreeLibrary(library);
    return passed;
}
