#include "TestSupport.h"

using namespace Detourist::Tests;

int TargetMain(int, wchar_t**)
{
    // A nonmatching first attribute exercises the API's loop back to its entry instructions.
    CRYPT_ATTRIBUTE attributes[]{
        {const_cast<LPSTR>("1.2.3.4"), 0, nullptr},
        {const_cast<LPSTR>("1.2.3.5"), 0, nullptr},
        {const_cast<LPSTR>("1.2.3.6"), 0, nullptr}};
    auto module = GetModuleHandleW(L"crypt32.dll");
    auto resolved = reinterpret_cast<decltype(&CertFindAttribute)>(GetProcAddress(module, "CertFindAttribute"));
    if (!resolved) return 1;
    for (int index = 0; index < 3; ++index)
    {
        if (CertFindAttribute("1.2.3.6", 3, attributes) != attributes + 2 ||
            CertFindAttribute("1.2.3.7", 3, attributes) || CertFindAttribute("1.2.3.6", 0, nullptr)) return 2;
        if (resolved("1.2.3.6", 3, attributes) != attributes + 2 ||
            resolved("1.2.3.7", 3, attributes) || resolved("1.2.3.6", 0, nullptr)) return 3;
    }
    return 0;
}

void CertificateLookup(const Context& context)
{
    RunTarget(context);
    Capture::Run(context, {.instructions = context.Has(L"--instructions")}, [&](Capture& capture)
    {
        auto calls = Named(TargetCalls(context, capture.database), "CertFindAttribute");
        Require(calls.size() == 18, "Imported or resolved certificate lookups were not captured", calls.size());
        auto found = std::count_if(calls.begin(), calls.end(), [](const Json& call)
        {
            return call["result"].get<uint64_t>() != 0;
        });
        Require(found == 6, "Certificate lookup results changed under capture");
        for (const auto& call : calls)
            Require(call["argument_count"] == 3 && !(call["flags"].get<uint32_t>() & (4 | 256)),
                "Certificate lookup lost its typed contract", call);
        capture.CheckDiagnostics(true);
    });
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, CertificateLookup); }
