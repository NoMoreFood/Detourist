#include "TestSupport.h"
#include <ws2spi.h>

using namespace Detourist::Tests;

int TargetMain(int, wchar_t**)
{
    // Opening an unconnected socket exercises the installed transport provider's startup table.
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 1;
    auto socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) { WSACleanup(); return 2; }
    auto result = closesocket(socket);
    WSACleanup();
    if (result) return 3;

    // Resolve each provider entry with its declared argument count, including the shorter RNG contract.
    HMODULE primitives = LoadLibraryW(L"bcryptprimitives.dll"), storage = LoadLibraryW(L"ncryptprov.dll");
    if (!primitives || !storage) return 4;
    using AlgorithmInterface = LONG (WINAPI*)(LPCWSTR, LPCWSTR, void**, ULONG);
    using ProviderInterface = LONG (WINAPI*)(LPCWSTR, void**, ULONG);
    struct Algorithm { const char* name; const wchar_t* algorithm; };
    const Algorithm algorithms[]{
        {"GetCipherInterface", BCRYPT_AES_ALGORITHM}, {"GetHashInterface", BCRYPT_SHA256_ALGORITHM},
        {"GetSignatureInterface", BCRYPT_ECDSA_P256_ALGORITHM},
        {"GetSecretAgreementInterface", BCRYPT_ECDH_P256_ALGORITHM},
        {"GetAsymmetricEncryptionInterface", BCRYPT_RSA_ALGORITHM},
        {"GetKeyDerivationInterface", BCRYPT_SP800108_CTR_HMAC_ALGORITHM}};
    for (const auto& algorithm : algorithms)
    {
        auto get = reinterpret_cast<AlgorithmInterface>(GetProcAddress(primitives, algorithm.name));
        void* table = nullptr;
        if (!get || get(MS_PRIMITIVE_PROVIDER, algorithm.algorithm, &table, 0) < 0 || !table) return 5;
    }
    auto rng = reinterpret_cast<ProviderInterface>(GetProcAddress(primitives, "GetRngInterface"));
    auto keys = reinterpret_cast<ProviderInterface>(GetProcAddress(storage, "GetKeyStorageInterface"));
    void* table = nullptr;
    if (!rng || rng(MS_PRIMITIVE_PROVIDER, &table, 0) < 0 || !table) return 6;
    table = nullptr;
    if (!keys || keys(L"Microsoft Software Key Storage Provider", &table, 0) < 0 || !table) return 7;
    FreeLibrary(storage);
    FreeLibrary(primitives);
    return 0;
}

void ProviderStartup(const Context& context)
{
    Capture::Run(context, {.limit = 1024, .instructions = context.Has(L"--instructions")}, [&](Capture& capture)
    {
        auto calls = Named(Calls(capture.database), "WSPStartup");
        Require(!calls.empty(), "Winsock provider startup was not captured.");
        for (const auto& call : calls)
        {
            Require(call["module"] == "mswsock.dll" && call["argument_count"] == 5 &&
                !(call["flags"].get<uint32_t>() & (4 | 256)), "Winsock provider startup contract differs", call);
            auto input = Regions(call["input"], {.parameter = 3});
            Require(!input.empty() && input[0].original == sizeof(WSPUPCALLTABLE),
                "Winsock upcall table was not captured by value.");
            auto output = Regions(call["output"], {.parameter = 4});
            Require(!output.empty() && output[0].original == sizeof(WSPPROC_TABLE),
                "Winsock provider table was not captured.");
        }
        for (const auto* name : {"GetCipherInterface", "GetHashInterface", "GetRngInterface",
            "GetSignatureInterface", "GetSecretAgreementInterface", "GetAsymmetricEncryptionInterface",
            "GetKeyDerivationInterface", "GetKeyStorageInterface"})
        {
            auto getters = Named(TargetCalls(context, capture.database), name);
            Require(!getters.empty(), std::string("CNG provider entry was not captured: ") + name);
            for (const auto& call : getters)
            {
                auto count = !strcmp(name, "GetRngInterface") || !strcmp(name, "GetKeyStorageInterface") ? 3u : 4u;
                Require(call["argument_count"] == count && !(call["flags"].get<uint32_t>() & (1 | 4 | 256)),
                    "CNG provider contract differs", call);
                auto output = Regions(call["output"], {.parameter = count - 2});
                Require(!output.empty() && output[0].original == sizeof(void*),
                    "CNG provider table pointer was not captured.");
            }
        }
        capture.CheckDiagnostics(true);
    });
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, ProviderStartup); }
