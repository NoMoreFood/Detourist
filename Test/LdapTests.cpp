#include "TestSupport.h"

#if defined(DETOURIST_TEST_DetouristBerVariadicTests)

using namespace Detourist::Tests;

template<size_t... Index>
bool RoundTripTail(char* bits, std::index_sequence<Index...>)
{
    // Exercise a complete tail, a pair straddling the capture boundary, and calls beyond that boundary.
    constexpr auto count = sizeof...(Index);
    auto writeFormat = "{" + std::string(count, 'i') + "sX}";
    auto readFormat = "{" + std::string(count, 'i') + "aB}";
    std::array<ber_int_t, count> integers{};
    char text[] = "BER late string";
    char* decodedText = nullptr;
    char* decodedBits = nullptr;
    ber_len_t bitCount = 0;
    auto encoded = ber_alloc_t(LBER_USE_DER);
    if (!encoded || ber_printf(encoded, writeFormat.data(),
        static_cast<ber_int_t>(count * 100000 + Index)..., text, bits, 9u) == -1) return false;
    BERVAL* flattened = nullptr;
    if (ber_flatten(encoded, &flattened) || !flattened) return false;
    auto decoded = ber_init(flattened);
    if (!decoded || ber_scanf(decoded, readFormat.data(), &integers[Index]...,
        &decodedText, &decodedBits, &bitCount) == LBER_ERROR) return false;
    const bool valid = ((integers[Index] == count * 100000 + Index) && ...) &&
        decodedText && !strcmp(decodedText, text) && decodedBits && bitCount == 9 && !memcmp(decodedBits, bits, 2);
    ldap_memfreeA(decodedText);
    ber_free(decoded, 1);
    ber_bvfree(flattened);
    ber_free(encoded, 1);
    return valid;
}

int TargetMain()
{
    // Round-trip every documented value token without contacting a directory service.
    char octets[] = {'A', 0, 'B', 'C'};
    char text[] = "Detourist BER text";
    char bits[] = {static_cast<char>(0xa5), static_cast<char>(0x80)};
    char first[] = "BER vector one", second[] = "BER vector two";
    char* strings[] = {first, second, nullptr};
    BERVAL binary{sizeof(octets), octets}, bitValue{sizeof(bits), bits};
    BERVAL* binaries[] = {&binary, &bitValue, nullptr};
    auto encoded = ber_alloc_t(LBER_USE_DER);
    if (!encoded) return 1;
    char writeFormat[] = "{tbienosX{v}{V}}";
    if (ber_printf(encoded, writeFormat, 0x81u, 1, 3, -7,
        octets, unsigned(sizeof(octets)), text, bits, 9u, strings, binaries) == -1) return 2;
    BERVAL* flattened = nullptr;
    if (ber_flatten(encoded, &flattened) || !flattened) return 3;
    auto decoded = ber_init(flattened);
    if (!decoded) return 4;
    ULONG firstLength = 0;
    if (ber_skip_tag(decoded, &firstLength) != 0x30 || ber_peek_tag(decoded, &firstLength) != 0x81) return 5;
    ber_free(decoded, 1);
    decoded = ber_init(flattened);
    if (!decoded) return 4;
    ber_int_t boolean = 0, enumeration = 0, integer = 0;
    BERVAL* readOctets = nullptr;
    char* readText = nullptr;
    char* readBits = nullptr;
    ber_len_t bitCount = 0;
    char** readStrings = nullptr;
    BERVAL** readBinaries = nullptr;
    char readFormat[] = "{beinOaBvV}";
    if (ber_scanf(decoded, readFormat, &boolean, &enumeration, &integer,
        &readOctets, &readText, &readBits, &bitCount, &readStrings, &readBinaries) == LBER_ERROR) return 5;
    if (!boolean || enumeration != 3 || integer != -7 || !readOctets ||
        readOctets->bv_len != sizeof(octets) || memcmp(readOctets->bv_val, octets, sizeof(octets)) ||
        !readText || strcmp(readText, text) || bitCount != 9 || !readBits ||
        memcmp(readBits, bits, sizeof(bits)) || !readStrings || !readStrings[0] || !readStrings[1] ||
        strcmp(readStrings[0], first) || strcmp(readStrings[1], second) || readStrings[2] ||
        !readBinaries || !readBinaries[0] || !readBinaries[1] || readBinaries[2] ||
        readBinaries[0]->bv_len != sizeof(octets) ||
        memcmp(readBinaries[0]->bv_val, octets, sizeof(octets)))
    {
        fprintf(stderr, "BER round trip: boolean=%d enum=%d integer=%d octets=%u text=%s bits=%u "
            "strings=%s,%s binaries=%u\n", boolean, enumeration, integer,
            readOctets ? readOctets->bv_len : 0, readText ? readText : "null", bitCount,
            readStrings && readStrings[0] ? readStrings[0] : "null",
            readStrings && readStrings[1] ? readStrings[1] : "null",
            readBinaries && readBinaries[0] ? readBinaries[0]->bv_len : 0);
        return 6;
    }
    ber_bvfree(readOctets);
    ldap_memfreeA(readText);
    for (auto value = readStrings; *value; ++value) ldap_memfreeA(*value);
    ldap_memfreeA(reinterpret_cast<char*>(readStrings));
    ber_bvecfree(readBinaries);
    ber_free(decoded, 1);
    ber_bvfree(flattened);
    ber_free(encoded, 1);

    // The installed decoder ignores its tag token without consuming an output argument.
    encoded = ber_alloc_t(LBER_USE_DER);
    char tagSource[] = "{i}";
    if (!encoded || ber_printf(encoded, tagSource, 7) == -1 || ber_flatten(encoded, &flattened)) return 13;
    decoded = ber_init(flattened);
    ber_tag_t tag = 0xA1B2C3D4;
    char tagFormat[] = "t";
    if (!decoded || ber_scanf(decoded, tagFormat, &tag) == LBER_ERROR || tag != 0xA1B2C3D4) return 14;
    ULONG tagLength = 0;
    if (ber_peek_tag(decoded, &tagLength) != 0x30) return 15;
    ber_free(decoded, 1);
    decoded = ber_init(flattened);
    ber_int_t taggedInteger = 0x12345678;
    char taggedFormat[] = "{ti}";
    if (!decoded || ber_scanf(decoded, taggedFormat, &taggedInteger) == LBER_ERROR || taggedInteger != 7)
        return 16;
    ber_free(decoded, 1);
    ber_bvfree(flattened);
    ber_free(encoded, 1);

    // Set delimiters and skip tokens consume no variable arguments.
    encoded = ber_alloc_t(LBER_USE_DER);
    char setFormat[] = "{[s]}";
    if (!encoded || ber_printf(encoded, setFormat, text) == -1 || ber_flatten(encoded, &flattened)) return 7;
    decoded = ber_init(flattened);
    char skipFormat[] = "{[x]}";
    if (!decoded || ber_scanf(decoded, skipFormat) == LBER_ERROR) return 8;
    ber_free(decoded, 1);
    ber_bvfree(flattened);
    ber_free(encoded, 1);

    // Failed decodes and zero-length inputs must not follow inaccessible output or input pointers.
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto guarded = static_cast<char*>(VirtualAlloc(nullptr, system.dwPageSize * 2,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!guarded) return 7;
    DWORD previous = 0;
    if (!VirtualProtect(guarded + system.dwPageSize, system.dwPageSize, PAGE_NOACCESS, &previous)) return 8;
    auto inaccessible = guarded + system.dwPageSize;
    encoded = ber_alloc_t(LBER_USE_DER);
    char zeroFormat[] = "o";
    if (!encoded || ber_printf(encoded, zeroFormat, inaccessible, 0u) == -1) return 9;
    auto guardedOctets = inaccessible - sizeof(octets);
    memcpy(guardedOctets, octets, sizeof(octets));
    if (ber_printf(encoded, zeroFormat, guardedOctets, unsigned(sizeof(octets))) == -1) return 10;
    BERVAL zero{0, inaccessible};
    BERVAL* zeroVector[] = {&zero, nullptr};
    char zeroVectorFormat[] = "{V}";
    if (ber_printf(encoded, zeroVectorFormat, zeroVector) == -1) return 10;
    char invalidFormat[] = "!s";
    if (ber_printf(encoded, invalidFormat, inaccessible) != -1) return 11;
    char emptySequence[] = {0x30, 0};
    BERVAL invalid{sizeof(emptySequence), emptySequence};
    decoded = ber_init(&invalid);
    char failFormat[] = "a";
    char* failedOutput = inaccessible;
    if (!decoded || ber_scanf(decoded, failFormat, &failedOutput) != LBER_ERROR) return 12;
    ber_free(decoded, 1);

    // The encoder rejects an unknown token while the decoder continues without consuming an argument.
    char unknownWrite[] = "{i!s}";
    if (ber_printf(encoded, unknownWrite, 65536, inaccessible) != -1) return 17;
    char unknownData[]{0x30, 0x07, 0x02, 0x01, 7, 0x04, 0x02, 'O', 'K'};
    BERVAL unknownValue{sizeof(unknownData), unknownData};
    decoded = ber_init(&unknownValue);
    char unknownRead[] = "{i!a}";
    ber_int_t partialInteger = -1;
    if (!decoded) return 18;
    auto unknownResult = ber_scanf(decoded, unknownRead, &partialInteger, &failedOutput);
    if (unknownResult == LBER_ERROR || partialInteger != 7 || failedOutput == inaccessible ||
        !failedOutput || strcmp(failedOutput, "OK"))
    {
        fprintf(stderr, "Unknown BER decode: result=%lu integer=%d pointerChanged=%d\n",
            unknownResult, partialInteger, failedOutput != inaccessible);
        return 18;
    }
    ldap_memfreeA(failedOutput);
    ber_free(decoded, 1);
    ber_free(encoded, 1);

    // Every unsupported byte, including high bytes, leaves scalar, allocated and paired arguments aligned.
    std::array<char, 16> paddedBits{char(0xA5), char(0x80)};
    char recoverySource[] = "{isXi}";
    char recoveryText[] = "OK";
    BERVAL* recoveryValue = nullptr;
    encoded = ber_alloc_t(LBER_USE_DER);
    if (!encoded || ber_printf(encoded, recoverySource, 7, recoveryText, paddedBits.data(), 9u, 9) == -1 ||
        ber_flatten(encoded, &recoveryValue) || !recoveryValue) return 20;
    for (unsigned token = 1; token < 256; ++token)
    {
        if (strchr("BOV[]abeintvx{}", token)) continue;
        auto ignored = static_cast<char>(token);
        char recoveryFormat[]{ignored, '{', 'i', ignored, 'a', ignored, 'B', ignored, 'i', '}', ignored, 0};
        ber_int_t first = -1, last = -1;
        ber_len_t length = 0;
        char* text = nullptr;
        char* outputBits = nullptr;
        decoded = ber_init(recoveryValue);
        if (!decoded) return 20;
        auto result = ber_scanf(decoded, recoveryFormat, &first, &text, &outputBits, &length, &last);
        if (result == LBER_ERROR || first != 7 || last != 9 || !text || strcmp(text, "OK") ||
            !outputBits || length != 9 || memcmp(outputBits, "\xA5\x80", 2))
        {
            fprintf(stderr, "BER recovery failed for token %u: result=%lu first=%d last=%d length=%lu\n",
                token, result, first, last, length);
            return 20;
        }
        ldap_memfreeA(text);
        ber_free(decoded, 1);
    }

    ber_bvfree(recoveryValue);
    ber_free(encoded, 1);

    // A later decoding failure does not establish ownership of earlier allocated outputs.
    decoded = ber_init(&unknownValue);
    char recoveryFailure[] = "!{i?ai}!";
    char* discarded = nullptr;
    ber_int_t missing = -1;
    if (!decoded || ber_scanf(decoded, recoveryFailure, &partialInteger, &discarded, &missing) != LBER_ERROR)
        return 21;
    ber_free(decoded, 1);

    // Native bit strings have readable padding; capture follows only the declared bit extent.
    auto guardedBits = inaccessible - 16;
    memset(guardedBits, 0, 16);
    memcpy(guardedBits, bits, sizeof(bits));

    // The native provider still receives and decodes arguments outside the recorded prefix.
    if (!RoundTripTail(guardedBits, std::make_index_sequence<19>{}) ||
        !RoundTripTail(guardedBits, std::make_index_sequence<27>{}) ||
        !RoundTripTail(guardedBits, std::make_index_sequence<28>{}) ||
        !RoundTripTail(guardedBits, std::make_index_sequence<34>{})) return 19;
    VirtualFree(guarded, 0, MEM_RELEASE);
    return 0;
}

void BerVariadic(const Context& context)
{
    RunTarget(context);
    Json inspections = Json::array();
    for (uint32_t limit : {16u, 24u, 64u})
    {
        Capture::Run(context, {.limit = limit}, [&](Capture& capture)
        {
            auto rows = capture.Find("ber_printf|ber_scanf", "wldap32\\.dll");
            Require(rows.size() == 264, "BER variadic call count differs", rows.size());
            for (const auto& row : rows)
            {
                Require(Data(row["arguments"]).size() == 256 && (row["flags"].get<uint32_t>() & 256),
                        "BER variadic ABI differs", row);
                CheckLimit(row, limit);
            }
            auto format = [&](const char* name, const Bytes& text, std::optional<uint64_t> size = {})
            {
                auto found = Select(Named(rows, name), [&](const Json& row)
                {
                    return (!size || Read<uint64_t>(row["arguments"], 24) == *size) &&
                           std::ranges::any_of(Regions(row["input"], {.parameter = 1}),
                                               [&](const Value& value) { return value.data == Prefix(text, limit); });
                });
                Require(!found.empty(), "BER format sample missing: " + std::string(name));
                return found[0];
            };
            auto present = [&](const auto& values, const RegionFilter& filter, const Bytes& bytes,
                               std::optional<uint64_t> original = {})
            {
                Require(std::ranges::any_of(Regions(values, filter), [&](const Value& value)
                { return value.data == bytes && (!original || value.original == *original); }),
                        "BER captured bytes differ");
            };
            auto noRange = [](const auto& values, uint32_t first, uint32_t last = UINT32_MAX)
            {
                Require(std::ranges::none_of(values, [&](const Value& value)
                { return value.index >= first && value.index <= last; }),
                        "BER unused argument was captured");
            };
            auto table = [&](const auto& values, uint32_t parameter, uint32_t required = 0)
            {
                auto array =
                    Only(Regions(values, {.parameter = parameter, .kind = 0, .required = required, .excluded = 64}));
                Require(array.data.size() == std::min(limit, 24u) && bool(array.flags & 1) == (limit < 24),
                        "BER pointer table bounds differ");
            };

            // Scalar encoders stay scalar; sized binary data and vectors preserve embedded nulls.
            auto encoded = format("ber_printf", Encode("{tbienosX{v}{V}}", false, true));
            auto before = Values(encoded["input"]), after = Values(encoded["output"]);
            noRange(before, 2, 5);
            noRange(after, 2, 12);
            auto binary = Bytes{'A', 0, 'B', 'C'}, bits = Bytes{0xa5, 0x80};
            present(before, {.parameter = 6}, binary, 4);
            present(before, {.parameter = 9}, bits, 2);
            present(before, {.parameter = 8}, Prefix(Encode("Detourist BER text", false, true), limit));
            for (uint32_t parameter : {11u, 12u})
                table(before, parameter);
            present(before, {.parameter = 12, .required = 64, .element = 0}, binary);
            present(before, {.parameter = 12, .required = 64, .element = 1}, bits);

            // Successful decoders follow only complete allocated descriptor prefixes.
            auto decoded = format("ber_scanf", Encode("{beinOaBvV}", false, true));
            before = Values(decoded["input"]);
            after = Values(decoded["output"]);
            noRange(before, 2, 10);
            for (auto [parameter, number] : {std::pair{2u, -1}, {3u, 3}, {4u, -7}, {8u, 9}})
                present(after, {.parameter = parameter, .kind = 2}, Integer(uint32_t(number), 4));
            present(after, {.parameter = 6, .required = 8}, Prefix(Encode("Detourist BER text", false, true), limit));
            present(after, {.parameter = 7, .required = 8}, bits, 2);
            present(after, {.parameter = 5, .required = 8}, binary, 4);
            present(after, {.parameter = 10, .required = 64, .element = 0}, binary);
            for (uint32_t parameter : {9u, 10u})
                table(after, parameter, 8);
            auto tagOnly = format("ber_scanf", Encode("t", false, true));
            noRange(Values(tagOnly["input"]), 2);
            noRange(Values(tagOnly["output"]), 2);
            auto tagged = format("ber_scanf", Encode("{ti}", false, true));
            present(Values(tagged["output"]), {.parameter = 2, .kind = 2}, Integer(7, 4));
            noRange(Values(tagged["output"]), 3);

            // Empty and failed values never follow inaccessible pointers.
            auto zero = format("ber_printf", Encode("o", false, true), 0);
            noRange(Values(zero["input"]), 2, 3);
            noRange(Values(zero["output"]), 2, 3);
            auto guarded = format("ber_printf", Encode("o", false, true), 4);
            present(Values(guarded["input"]), {.parameter = 2, .excluded = 2}, binary, 4);
            auto vector = format("ber_printf", Encode("{V}", false, true));
            auto reference = Only(Regions(vector["input"], {.parameter = 2, .required = 64}));
            Require(reference.original == 16 && reference.data.size() == 16, "Empty BERVAL descriptor differs");
            auto skipped = format("ber_scanf", Encode("{[x]}", false, true));
            Require(uint32_t(Number(skipped["result"])) != UINT32_MAX, "BER skip decode failed", skipped);
            auto failed = format("ber_scanf", Encode("a", false, true));
            Require(Regions(failed["input"], {.parameter = 2}).empty() &&
                        Regions(failed["output"], {.parameter = 2}).empty(),
                    "Failed BER allocation was dereferenced", failed);
            auto unknown = format("ber_printf", Encode("!s", false, true));
            present(Values(unknown["input"]), {.parameter = 2, .required = 2}, {});
            for (bool encode : {true, false})
            {
                auto row = format(encode ? "ber_printf" : "ber_scanf", Encode(encode ? "{i!s}" : "{i!a}", false, true));
                before = Values(row["input"]);
                after = Values(row["output"]);
                Require(Regions(before, {.parameter = 2}).empty(), "BER scalar was probed as input", row);
                if (encode)
                {
                    auto fallback = Only(Regions(before, {.parameter = 3}));
                    Require(fallback.original == limit && (fallback.flags & 2) && fallback.data.empty() &&
                                uint32_t(Number(row["result"])) == UINT32_MAX &&
                                Regions(after, {.parameter = 2}).empty(),
                            "Unknown BER encoder token fallback differs", row);
                }
                else
                {
                    Require(uint32_t(Number(row["result"])) != UINT32_MAX, "Ignored BER decoder token failed", row);
                    noRange(before, 2);
                    present(after, {.parameter = 2, .kind = 2}, Integer(7, 4));
                    present(after, {.parameter = 3, .required = 8}, Encode("OK", false, true));
                }
            }

            // Every ignored token byte preserves later argument identities and completed outputs.
            std::map<Bytes, Json> decodes;
            for (const auto& row : Named(rows, "ber_scanf"))
                for (const auto& value : Regions(row["input"], {.parameter = 1}))
                    decodes[value.data] = row;
            for (uint32_t token = 1; token < 256; ++token)
            {
                if (std::string_view("BOV[]abeintvx{}").contains(static_cast<char>(token))) continue;
                auto ch = static_cast<uint8_t>(token);
                Bytes text{ch, '{', 'i', ch, 'a', ch, 'B', ch, 'i', '}', ch, 0};
                auto row = decodes.at(text);
                before = Values(row["input"]);
                after = Values(row["output"]);
                Require(uint32_t(Number(row["result"])) != UINT32_MAX, "Ignored BER token decode failed", row);
                noRange(before, 2);
                for (auto [index, expected] : {std::pair{2u, 7}, {5u, 9}, {6u, 9}})
                    present(after, {.parameter = index, .kind = 2}, Integer(expected, 4));
                for (auto [index, bytes] : {std::pair{3u, Encode("OK", false, true)}, {4u, bits}})
                {
                    auto pointer = Regions(after, {.parameter = index, .kind = 2});
                    Require(std::ranges::any_of(pointer, [](const Value& value)
                    { return value.data.size() == 8 && Read<uint64_t>(value.data); }),
                            "BER allocated output pointer missing", row);
                    auto value = Only(Regions(after, {.parameter = index, .required = 8}));
                    Require(value.flags == 8 && value.original == bytes.size() && value.data == bytes,
                            "Ignored BER token changed allocated output", row);
                }
                noRange(after, 7);
            }
            failed = decodes.at(Encode("!{i?ai}!", false, true));
            Require(uint32_t(Number(failed["result"])) == UINT32_MAX, "Failed BER sequence succeeded", failed);
            noRange(Values(failed["input"]), 2);
            noRange(Values(failed["output"]), 2);

            // Late strings and complete bit pairs stay typed; an incomplete pair remains raw at slot 31.
            for (uint32_t count : {19u, 27u, 28u, 34u})
                for (bool encode : {true, false})
                {
                    auto samples = Select(Named(rows, encode ? "ber_printf" : "ber_scanf"), [&](const Json& row)
                    {
                        return encode ? Read<uint32_t>(row["arguments"], 16) == count * 100000
                                      : std::ranges::any_of(Regions(row["output"], {.parameter = 2, .kind = 2}),
                                                            [&](const Value& value)
                        { return value.data == Integer(count * 100000, 4); });
                    });
                    auto row = Only(samples);
                    before = Values(row["input"]);
                    after = Values(row["output"]);
                    for (uint32_t index = 2; index < std::min(32u, count + 2); ++index)
                    {
                        Require(Regions(before, {.parameter = index}).empty(), "Late BER scalar was dereferenced", row);
                        if (encode)
                            Require(Read<uint32_t>(row["arguments"], index * 8) == count * 100000 + index - 2 &&
                                        Regions(after, {.parameter = index}).empty(),
                                    "Late BER encoder scalar differs", row);
                        else
                            present(after, {.parameter = index, .kind = 2}, Integer(count * 100000 + index - 2, 4));
                    }
                    const auto& captured = encode ? before : after;
                    if (count <= 28)
                        present(captured, {.parameter = count + 2, .kind = 0}, Encode("BER late string", false, true));
                    if (count <= 27)
                    {
                        present(captured, {.parameter = count + 3, .excluded = 2}, bits, 2);
                        noRange(before, count + 5);
                        noRange(after, count + 5);
                    }
                    if (count == 28)
                    {
                        auto raw = Only(Regions(captured, {.parameter = 31}));
                        Require(raw.kind == 0 && !(raw.flags & 8) && raw.original == limit,
                                "Incomplete BER bit pair was decoded", row);
                    }
                }
            if (!context.Optional(0).empty())
                for (const auto& row : rows)
                {
                    auto detail = capture.Details(row);
                    inspections.push_back({{"limit", limit}, {"call", detail}});
                    if (row["name"] != "ber_printf") continue;
                    auto elements = Select(detail["input"], [](const Json& value)
                    { return value["parameter"] == 12 && value.value("elementIndex", -1) == 0; });
                    if (elements.empty()) continue;
                    auto partial = detail, tablePrefix = detail;
                    Json input = Json::array();
                    bool first = true;
                    for (auto value : partial["input"])
                    {
                        if (value["parameter"] == 12 && value.value("elementIndex", -1) == 0)
                        {
                            if (!first) continue;
                            first = false;
                            value["bytes"] = value["bytes"].get<std::string>().substr(0, 24);
                            value["flags"] = value["flags"].get<uint32_t>() | 1;
                        }
                        input.push_back(value);
                    }
                    partial["input"] = input;
                    inspections.push_back({{"limit", limit}, {"call", partial}});
                    input = Json::array();
                    for (auto value : tablePrefix["input"])
                    {
                        if (value["parameter"] == 12 && !value.contains("elementIndex"))
                        {
                            value["bytes"] = value["bytes"].get<std::string>().substr(0, 8);
                            value["flags"] = value["flags"].get<uint32_t>() | 1;
                        }
                        if (value["parameter"] != 12 || value.value("elementIndex", 0) == 0) input.push_back(value);
                    }
                    tablePrefix["input"] = input;
                    inspections.push_back({{"limit", limit}, {"call", tablePrefix}});
                }
        }, 60);
    }
    if (!context.Optional(1).empty()) WriteJson(context.Optional(1), inspections);
    Inspect(context, context.Optional(0), "--ber-variadic", inspections, 30000);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, BerVariadic); }

#elif defined(DETOURIST_TEST_DetouristLdapModTests)

using namespace Detourist::Tests;
static_assert(sizeof(LDAPModA) == 24 && offsetof(LDAPModA, mod_type) == 8 &&
    offsetof(LDAPModA, mod_vals) == 16 && sizeof(BERVAL) == 16 && offsetof(BERVAL, bv_val) == 8);


__declspec(noinline) ULONG Request(FARPROC function, bool extended, bool synchronous,
    void* distinguishedName, void* modifications)
{
    ULONG message = 0;
    if (!extended)
        return reinterpret_cast<ULONG(WINAPI*)(LDAP*, void*, void*)>(function)(
            nullptr, distinguishedName, modifications);
    if (synchronous)
        return reinterpret_cast<ULONG(WINAPI*)(LDAP*, void*, void*, void*, void*)>(function)(
            nullptr, distinguishedName, modifications, nullptr, nullptr);
    return reinterpret_cast<ULONG(WINAPI*)(LDAP*, void*, void*, void*, void*, ULONG*)>(function)(
        nullptr, distinguishedName, modifications, nullptr, nullptr, &message);
}

int TargetMain()
{
    auto provider = LoadLibraryExW(L"wldap32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!provider) return 1;
    char first[] = "LDAP text first", second[] = "LDAP text second";
    wchar_t wideFirst[] = L"LDAP text first", wideSecond[] = L"LDAP text second";
    char* text[] = {first, second, nullptr};
    wchar_t* wideText[] = {wideFirst, wideSecond, nullptr};
    char binary[] = {0x12, 0x00, 0x34, 0x56, 0x00, 0x78, 0x7f};
    char large[96];
    for (uint32_t index = 0; index < sizeof(large); ++index) large[index] = static_cast<char>(index);
    BERVAL shortValue{sizeof(binary), binary}, longValue{sizeof(large), large};
    BERVAL empty{0, reinterpret_cast<char*>(1)};
    BERVAL* binaryValues[] = {&shortValue, &longValue, &empty, nullptr};
    LDAPModA ansi[3]{};
    LDAPModW wide[3]{};
    char attribute0[] = "displayName", attribute1[] = "jpegPhoto", attribute2[] = "obsoleteAttribute";
    wchar_t wideAttribute0[] = L"displayName", wideAttribute1[] = L"jpegPhoto",
        wideAttribute2[] = L"obsoleteAttribute";
    ansi[0].mod_op = LDAP_MOD_REPLACE;
    ansi[0].mod_type = attribute0;
    ansi[0].mod_vals.modv_strvals = text;
    wide[0].mod_op = LDAP_MOD_REPLACE;
    wide[0].mod_type = wideAttribute0;
    wide[0].mod_vals.modv_strvals = wideText;
    ansi[1].mod_op = wide[1].mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
    ansi[1].mod_type = attribute1;
    wide[1].mod_type = wideAttribute1;
    ansi[1].mod_vals.modv_bvals = wide[1].mod_vals.modv_bvals = binaryValues;
    ansi[2].mod_op = wide[2].mod_op = LDAP_MOD_DELETE;
    ansi[2].mod_type = attribute2;
    wide[2].mod_type = wideAttribute2;
    LDAPModA* ansiModifications[] = {ansi, ansi + 1, ansi + 2, nullptr};
    LDAPModW* wideModifications[] = {wide, wide + 1, wide + 2, nullptr};
    char distinguishedName[] = "cn=Detourist,dc=invalid";
    wchar_t wideDistinguishedName[] = L"cn=Detourist,dc=invalid";

    // Invalid handles exercise the installed provider entry points without connecting to a directory.
    constexpr std::array names = {
        "ldap_add", "ldap_addA", "ldap_addW", "ldap_add_s", "ldap_add_sA", "ldap_add_sW",
        "ldap_add_ext", "ldap_add_extA", "ldap_add_extW", "ldap_add_ext_s", "ldap_add_ext_sA",
        "ldap_add_ext_sW", "ldap_modify", "ldap_modifyA", "ldap_modifyW", "ldap_modify_s",
        "ldap_modify_sA", "ldap_modify_sW", "ldap_modify_ext", "ldap_modify_extA", "ldap_modify_extW",
        "ldap_modify_ext_s", "ldap_modify_ext_sA", "ldap_modify_ext_sW"};
    for (auto name : names)
    {
        auto function = GetProcAddress(provider, name);
        if (!function) return 2;
        auto unicode = name[std::strlen(name) - 1] == 'W';
        auto result = Request(function, std::strstr(name, "_ext") != nullptr,
            std::strstr(name, "_s") != nullptr, unicode ? static_cast<void*>(wideDistinguishedName) :
                distinguishedName, unicode ? static_cast<void*>(wideModifications) : ansiModifications);
        std::printf("PROVIDER %s %lu\n", name, result);
        if (result != LDAP_PARAM_ERROR && result != ULONG_MAX) return 3;
    }

    // A guarded descriptor cannot expose its union pointer until the complete descriptor was captured.
    auto guard = static_cast<BYTE*>(VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    DWORD previous = 0;
    if (!guard || !VirtualProtect(guard + 4096, 4096, PAGE_NOACCESS, &previous)) return 4;
    auto partial = reinterpret_cast<LDAPModW*>(guard + 4096 - 16);
    partial->mod_op = LDAP_MOD_REPLACE;
    partial->mod_type = reinterpret_cast<PWCHAR>(1);
    LDAPModW* guarded[] = {partial, nullptr};
    auto modify = GetProcAddress(provider, "ldap_modifyW");
    wchar_t descriptorName[] = L"1";
    auto result = Request(modify, false, false, descriptorName, guarded);
    if (result != LDAP_PARAM_ERROR && result != ULONG_MAX) return 5;

    // Unterminated pointer prefixes remain traversable only through the slots already recorded.
    auto pointer = reinterpret_cast<uint64_t*>(guard + 4096 - 8);
    *pointer = reinterpret_cast<uint64_t>(wide);
    wchar_t rootName[] = L"2";
    result = Request(modify, false, false, rootName, pointer);
    if (result != LDAP_PARAM_ERROR && result != ULONG_MAX) return 6;

    // A partial BERVAL must not expose a data pointer beyond the recorded descriptor.
    auto partialBinary = reinterpret_cast<BERVAL*>(pointer);
    partialBinary->bv_len = 7;
    BERVAL* guardedBinary[] = {partialBinary, nullptr};
    LDAPModW binaryModification{};
    binaryModification.mod_op = LDAP_MOD_BVALUES;
    binaryModification.mod_type = wideAttribute1;
    binaryModification.mod_vals.modv_bvals = guardedBinary;
    LDAPModW* binaryModifications[] = {&binaryModification, nullptr};
    wchar_t binaryName[] = L"3";
    result = Request(modify, false, false, binaryName, binaryModifications);
    if (result != LDAP_PARAM_ERROR && result != ULONG_MAX) return 7;

    // A guarded value array can still yield its complete, readable first value.
    *pointer = reinterpret_cast<uint64_t>(wideFirst);
    LDAPModW textModification{};
    textModification.mod_type = wideAttribute0;
    textModification.mod_vals.modv_strvals = reinterpret_cast<PWCHAR*>(pointer);
    LDAPModW* textModifications[] = {&textModification, nullptr};
    wchar_t valuesName[] = L"4";
    result = Request(modify, false, false, valuesName, textModifications);
    if (result != LDAP_PARAM_ERROR && result != ULONG_MAX) return 8;
    std::puts("GUARDED descriptor, root pointers, BERVAL and value pointers rejected without caller reads");
    VirtualFree(guard, 0, MEM_RELEASE);
    FreeLibrary(provider);
    return 0;
}

void LdapMod(const Context& context)
{
    // Preserve provider coverage and compare bounded text, binary, and guarded descriptor graphs.
    auto catalog =
        Query(context.collector.parent_path() / "ApiCatalog.sqlite",
              "SELECT f.name,cp.kind,cp.flags FROM functions f JOIN capture_parameters cp ON cp.function_id=f.id "
              "WHERE lower(f.module)='wldap32.dll' AND cp.ordinal=2 AND f.name IN ('ldap_addA','ldap_addW')");
    Require(catalog.size() == 2, "LDAP modification contracts missing", catalog);
    for (const auto& row : catalog)
        Require(row["kind"] == (row["name"] == "ldap_addW" ? 15 : 14) && row["flags"] == 1,
                "LDAP modification capture plan differs", row);
    auto baseline = RunTarget(context);
    std::set<std::string> requested;
    std::regex provider("PROVIDER (\\S+)");
    for (std::sregex_iterator it(baseline.begin(), baseline.end(), provider), end; it != end; ++it)
    {
        auto name = (*it)[1].str();
        if (name.ends_with('A')) name.pop_back();
        requested.insert(name);
    }
    Require(std::distance(std::sregex_iterator(baseline.begin(), baseline.end(), provider), std::sregex_iterator()) ==
                    24 &&
                baseline.contains("GUARDED"),
            "LDAP provider baseline incomplete");
    Json details = Json::array();
    for (uint32_t limit : {16u, 24u, 64u})
    {
        Capture::Run(context, {.limit = limit}, [&](Capture& capture)
        {
            auto rows = capture.Find("ldap_(add|modify).*", "wldap32\\.dll");
            Require(rows.size() >= 28, "LDAP modification calls missing", rows);
            std::set<std::string> observed;
            std::map<int, Json> guards;
            Json ansi, wide;
            for (const auto& row : rows)
            {
                auto name = row["name"].get<std::string>();
                if (name.ends_with('W'))
                {
                    if (wide.is_null()) wide = row;
                }
                else
                {
                    if (ansi.is_null()) ansi = row;
                }
                if (name.ends_with('A')) name.pop_back();
                observed.insert(name);
                auto marker = Regions(row["input"], {.parameter = 1, .kind = 1});
                if (!marker.empty() && marker[0].data.size() >= 2)
                {
                    auto first = Read<uint16_t>(marker[0].data);
                    if (first >= '1' && first <= '4') guards[first - '0'] = row;
                }
            }
            Require(std::ranges::includes(observed, requested) && guards.size() == 4 && !ansi.is_null() &&
                        !wide.is_null(),
                    "LDAP provider or guarded coverage missing", rows);
            auto ldap = [](const Json& payload)
            { return Regions(payload, {.parameter = 2, .required = 128, .parameterMask = 255}); };
            auto isGuarded = [&](const Json& row)
            { return std::ranges::any_of(guards, [&](const auto& pair) { return pair.second["id"] == row["id"]; }); };
            for (const auto& row : rows)
            {
                auto result = static_cast<uint32_t>(Number(row["result"]));
                auto parameters = row["parameters"].get<std::string>();
                Require(!(row["flags"].get<uint32_t>() & 256) && (result == 89 || result == UINT32_MAX) &&
                            ldap(row["output"]).empty() && parameters.contains("ld") && parameters.contains("dn") &&
                            (parameters.contains("mods") || parameters.contains("attrs")),
                        "LDAP modification contract differs", row);
                CheckLimit(row, limit);
                auto values = ldap(row["input"]);
                auto rootSize = row["id"] == guards.at(2)["id"] ? 8u : isGuarded(row) ? 16u : 32u;
                Require(std::ranges::any_of(Regions(values, {.tag = 0, .tagMask = 15}), [&](const Value& value)
                { return value.data.size() == std::min(rootSize, limit); }),
                        "LDAP modification root size differs", row);
                if (limit < 24)
                    for (const auto& value : values)
                        Require(((value.flags >> 8) & 15) <= 1 &&
                                    (row["id"] == guards.at(2)["id"] || !(value.flags & 2)),
                                "Capped LDAP modification descriptors were followed", row);
                if (limit < 32 && !isGuarded(row))
                    Require(!Regions(values, {.required = 1, .tag = 0, .tagMask = 15}).empty() &&
                                Regions(values, {.tag = 0, .tagMask = 15})[0].original == 0,
                            "LDAP root truncation metadata differs", row);
            }
            if (limit == 64)
            {
                for (const auto& row : {ansi, wide})
                {
                    bool unicode = row["name"].get<std::string>().ends_with('W');
                    auto values = ldap(row["input"]);
                    uint32_t modification = 0;
                    for (auto attribute : {"displayName", "jpegPhoto", "obsoleteAttribute"})
                    {
                        auto fields = Regions(values, {.tag = 2, .record = modification++, .tagMask = 15});
                        Require(std::ranges::any_of(fields, [&](const Value& value)
                        { return value.data == Encode(attribute, unicode, true); }),
                                "LDAP attribute name differs", row);
                    }
                    uint32_t index = 0;
                    for (auto text : {"LDAP text first", "LDAP text second"})
                    {
                        auto fields = Regions(values, {.element = index++, .tag = 4, .record = 0, .tagMask = 15});
                        Require(std::ranges::any_of(fields, [&](const Value& value)
                        { return value.data == Encode(text, unicode, true); }),
                                "LDAP text modification differs", row);
                    }
                    auto binary = Regions(values, {.element = 0, .tag = 6, .record = 1, .tagMask = 15});
                    Require(std::ranges::any_of(binary, [](const Value& value)
                    { return value.original == 7 && value.data == Bytes{0x12, 0, 0x34, 0x56, 0, 0x78, 0x7f}; }),
                            "LDAP binary modification differs", row);
                    Bytes sequence(64);
                    for (size_t i = 0; i < sequence.size(); ++i)
                        sequence[i] = static_cast<uint8_t>(i);
                    binary = Regions(values, {.required = 1, .element = 1, .tag = 6, .record = 1, .tagMask = 15});
                    Require(std::ranges::any_of(binary, [&](const Value& value)
                    { return value.original == 96 && value.data == sequence; }),
                            "LDAP binary truncation differs", row);
                    auto empty = Regions(values, {.element = 2, .tag = 5, .record = 1, .tagMask = 15});
                    Require(
                        std::ranges::any_of(empty, [](const Value& value) { return Starts(value.data, Bytes(4)); }) &&
                            Regions(values, {.element = 2, .tag = 6, .record = 1, .tagMask = 15}).empty(),
                        "Empty LDAP binary value was dereferenced", row);
                    for (const auto& value : Regions(values, {.record = 2}))
                        Require(((value.flags >> 8) & 15) < 3, "Deleted LDAP attribute has captured values", row);
                }
                auto first = ldap(guards.at(1)["input"]), second = ldap(guards.at(2)["input"]);
                auto third = ldap(guards.at(3)["input"]), fourth = ldap(guards.at(4)["input"]);
                auto unreadable = [](const auto& values, uint32_t tag)
                {
                    return std::ranges::any_of(Regions(values, {.required = 2, .tag = tag, .tagMask = 15}),
                                               [](const Value& value) { return value.data.empty(); });
                };
                Require(unreadable(first, 1) && std::ranges::all_of(first, [](const Value& value)
                { return ((value.flags >> 8) & 15) <= 1; }),
                        "Unreadable LDAP modification was followed");
                Require(unreadable(third, 5) && Regions(third, {.tag = 6, .tagMask = 15}).empty(),
                        "Partial LDAP binary header was followed");
                auto partial = [](const auto& values, uint32_t tag)
                {
                    return std::ranges::any_of(Regions(values, {.required = 3, .tag = tag, .tagMask = 15}),
                                               [](const Value& value)
                    { return value.original == 0 && value.data.size() == 8; });
                };
                Require(partial(fourth, 3) &&
                            std::ranges::any_of(Regions(fourth, {.tag = 4, .tagMask = 15}), [](const Value& value)
                { return value.data == Encode("LDAP text first", true, true); }),
                        "Partial LDAP value table differs");
                Require(partial(second, 0) && !Regions(second, {.tag = 4, .tagMask = 15}).empty(),
                        "Partial LDAP root table differs");
            }
            auto append = [&](const Json& row)
            {
                details.push_back({{"family", "ldap"},
                                   {"call", capture.Details(row)},
                                   {"parameter", 2},
                                   {"limit", limit},
                                   {"guarded", isGuarded(row)}});
            };
            append(ansi);
            append(wide);
            for (const auto& [marker, row] : guards)
                append(row);
        }, 60);
    }
    auto detailsPath = context.Option(L"--details");
    if (!detailsPath.empty()) WriteJson(detailsPath, details);
    if (!context.Optional(0).empty()) Inspect(context, context.Optional(0), "--buffer-elements", details);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, LdapMod); }

#elif defined(DETOURIST_TEST_DetouristLdapControlTests)

using namespace Detourist::Tests;
struct ControlLayout
{
    void* oid;
    BERVAL value;
    BOOLEAN critical;
};


static_assert(sizeof(BERVAL) == 16 && offsetof(BERVAL, bv_val) == 8);
static_assert(sizeof(LDAPControlA) == 32 && sizeof(LDAPControlW) == 32 && sizeof(ControlLayout) == 32);
static_assert(offsetof(LDAPControlA, ldctl_value) == 8 && offsetof(LDAPControlW, ldctl_iscritical) == 24);

int TargetMain(int count, wchar_t** arguments)
{
    if (count != 2) return 1;
    std::ofstream report{std::filesystem::path(arguments[1])};
    if (!report) return 2;
    auto provider = LoadLibraryW(L"wldap32.dll");
    auto connection = ldap_initW(const_cast<PWCHAR>(L"127.0.0.1"), LDAP_PORT);
    if (!provider || !connection) return 3;
    using Create = ULONG(LDAPAPI*)(LDAP*, ULONG, BERVAL*, UCHAR, void**);
    using Parse = ULONG(LDAPAPI*)(LDAP*, void**, ULONG*, BERVAL**);
    using Free = ULONG(LDAPAPI*)(void*);
    auto emit = [&](const char* stage, const char* name, FARPROC entry, ULONG page, ULONG result,
                    const void* input, const BERVAL* encoded, const BERVAL* cookie)
    {
        report << stage << '\t' << name << '\t' << std::hex
            << reinterpret_cast<uintptr_t>(entry) - reinterpret_cast<uintptr_t>(provider) << '\t'
            << page << '\t' << result << '\t' << reinterpret_cast<uintptr_t>(input) << '\t';
        for (unsigned part = 0; part < 2; ++part)
        {
            auto value = part ? cookie : encoded;
            if (value)
                for (ULONG index = 0; index < value->bv_len; ++index)
                    report << std::setw(2) << std::setfill('0') << unsigned(BYTE(value->bv_val[index]));
            if (!part) report << '\t';
        }
        report << '\n';
    };
    const char* createNames[] = {"ldap_create_page_controlW", "ldap_create_page_controlA", "ldap_create_page_control"};
    const char* parseNames[] = {"ldap_parse_page_controlW", "ldap_parse_page_controlA", "ldap_parse_page_control"};
    const char* freeNames[] = {"ldap_control_freeW", "ldap_control_freeA", "ldap_control_free"};
    char binary[96];
    for (unsigned index = 0; index < sizeof(binary); ++index) binary[index] = static_cast<char>(index * 13);

    // Build and parse genuine provider-owned controls without binding or contacting a directory server.
    for (unsigned variant = 0; variant < 3; ++variant)
    {
        auto createEntry = GetProcAddress(provider, createNames[variant]);
        auto parseEntry = GetProcAddress(provider, parseNames[variant]);
        auto freeEntry = GetProcAddress(provider, freeNames[variant]);
        if (!createEntry || !parseEntry || !freeEntry) return 4;
        for (unsigned sample = 0; sample < 3; ++sample)
        {
            BERVAL input{sample ? 0u : ULONG(sizeof(binary)), sample ? reinterpret_cast<char*>(1) : binary};
            auto cookie = sample == 2 ? nullptr : &input;
            auto page = ULONG(5000 + variant * 100 + sample);
            void* returned = nullptr;
            auto result = reinterpret_cast<Create>(createEntry)(connection, page, cookie, 1, &returned);
            if (result || !returned) return 5;
            auto control = static_cast<ControlLayout*>(returned);
            emit("CREATE", createNames[variant], createEntry, page, result, cookie, &control->value, cookie);
            char ignoredData[] = {4, 1, 0};
            ControlLayout ignored{variant ? static_cast<void*>(const_cast<char*>("1.2.3.4")) :
                static_cast<void*>(const_cast<wchar_t*>(L"1.2.3.4")), {sizeof(ignoredData), ignoredData}, 0};
            void* controls[] = {&ignored, returned, nullptr};
            ULONG total = 0;
            BERVAL* parsed = nullptr;
            result = reinterpret_cast<Parse>(parseEntry)(connection, controls, &total, &parsed);
            if (result || !parsed || total != page || parsed->bv_len != (cookie ? cookie->bv_len : 0) ||
                parsed->bv_len && memcmp(parsed->bv_val, binary, sizeof(binary))) return 6;
            emit("PARSE", parseNames[variant], parseEntry, page, result, controls, &control->value, parsed);
            ber_bvfree(parsed);
            reinterpret_cast<Free>(freeEntry)(returned);
        }
    }

    // Invalid sessions keep the provider from consuming deliberately inaccessible caller buffers.
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto memory = static_cast<BYTE*>(VirtualAlloc(nullptr, system.dwPageSize * 2,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!memory) return 7;
    auto boundary = memory + system.dwPageSize;
    DWORD previous = 0;
    if (!VirtualProtect(boundary, system.dwPageSize, PAGE_NOACCESS, &previous)) return 8;
    auto createEntry = GetProcAddress(provider, createNames[0]);
    auto parseEntry = GetProcAddress(provider, parseNames[0]);
    BERVAL partialCookie{64, reinterpret_cast<char*>(1)};
    auto partial = boundary - 12;
    memcpy(partial, &partialCookie, 12);
    void* output = reinterpret_cast<void*>(1);
    auto result = reinterpret_cast<Create>(createEntry)(nullptr, 6000, reinterpret_cast<BERVAL*>(partial), 1, &output);
    if (!result) return 9;
    emit("PARTIALCOOKIE", createNames[0], createEntry, 6000, result, partial, nullptr, nullptr);
    void* completeArrays[3][2]{};
    for (unsigned sample = 0; sample < 3; ++sample)
    {
        ControlLayout inaccessible{reinterpret_cast<void*>(1), {64, reinterpret_cast<char*>(1)}, 1};
        auto shortControl = boundary - 16;
        memcpy(shortControl, &inaccessible, 16);
        auto completeArray = completeArrays[sample];
        completeArray[0] = sample ? static_cast<void*>(&inaccessible) : static_cast<void*>(shortControl);
        auto shortArray = boundary - 4;
        memcpy(shortArray, completeArray, 4);
        auto controls = sample == 2 ? reinterpret_cast<void**>(shortArray) : completeArray;
        ULONG total = 0xdeadbeef;
        BERVAL* cookie = reinterpret_cast<BERVAL*>(1);
        result = reinterpret_cast<Parse>(parseEntry)(nullptr, controls, &total, &cookie);
        if (!result) return 10;
        emit(sample == 0 ? "PARTIALCONTROL" : sample == 1 ? "BADREFERENCES" : "PARTIALARRAY",
            parseNames[0], parseEntry, 6001 + sample, result, controls, nullptr, nullptr);
    }
    VirtualFree(memory, 0, MEM_RELEASE);
    ldap_unbind(connection);
    FreeLibrary(provider);
    return report ? 0 : 11;
}

Json ControlReport(const Path& path)
{
    auto rows = Columns(path, {"stage", "name", "rva", "page", "result", "address", "encoded", "cookie"}, {},
                        {"rva", "page", "result", "address"});
    Require(rows.size() == 22, "LDAP control report is incomplete", rows);
    return rows;
}

void LdapControl(const Context& context)
{
    // Compare local paging roundtrips with an independent native baseline.
    auto report = context.directory / L"controls.tsv";
    RunTarget(context, Quote(report));
    auto baseline = Group(ControlReport(report), {"stage", "name", "page"});
    Json details = Json::array();
    for (uint32_t limit : {16u, 64u})
    {
        Capture::Run(context, {.arguments = Quote(report), .limit = limit, .apiMask = 1ull << 19}, [&](Capture& capture)
        {
            std::map<std::string, Json> exports;
            for (const auto& item : capture.collector.Call("exports", {{"path", "C:\\Windows\\System32\\wldap32.dll"}}))
                exports[item["name"]] = item;
            std::map<std::string, Json> expected, failures;
            for (auto row : ControlReport(report))
            {
                auto native = baseline.at(Key(row, {"stage", "name", "page"}))[0];
                Require(Without(row, {"rva", "address"}) == Without(native, {"rva", "address"}),
                        "LDAP paging roundtrip differs", row);
                auto item = exports.at(row["name"].get<std::string>());
                Require(item["forwarder"] == "", "LDAP paging export is forwarded", item);
                row["rva"] = item["rva"];
                if (row["result"] == 0)
                    expected[Key(row, {"stage", "rva", "page"})] = row;
                else
                    failures[Key(row, {"rva", "address"})] = row;
            }
            auto rows = capture.Find("ldap_(create_page_control|parse_page_control|control_free).*", "wldap32\\.dll");
            std::set<std::string> seen, guarded, expectedGuards;
            std::set<uint64_t> freed, expectedFreed;
            for (const auto& [key, row] : failures)
                expectedGuards.insert(row["stage"].get<std::string>());
            for (auto name : {"ldap_control_free", "ldap_control_freeA", "ldap_control_freeW"})
                expectedFreed.insert(Number(exports.at(name)["rva"]));
            for (const auto& row : rows)
            {
                auto name = row["name"].get<std::string>();
                auto result = static_cast<uint32_t>(Number(row["result"]));
                Require(!(row["flags"].get<uint32_t>() & 256), "LDAP paging contract is raw", row);
                auto ldap = [](const Json& payload, uint32_t parameter)
                { return Regions(payload, {.parameter = parameter, .required = 128, .parameterMask = 255}); };
                auto part = [](const auto& values, uint32_t tag, uint32_t record = 0)
                { return Regions(values, {.tag = tag, .record = record}); };
                if (name.starts_with("ldap_control_free"))
                {
                    Require(!part(ldap(row["input"], 0), 7).empty() && ldap(row["output"], 0).empty(),
                            "Freed LDAP control snapshot differs", row);
                    freed.insert(Number(exports.at(name)["rva"]));
                    continue;
                }
                bool create = name.starts_with("ldap_create_page_control");
                auto count = create ? 5u : 4u;
                Require(row["argument_count"] == count && Data(row["arguments"]).size() == count * 8,
                        "LDAP paging argument count differs", row);
                auto rva = exports.at(name)["rva"];
                auto before = ldap(row["input"], create ? 2 : 1);
                auto after = ldap(row["output"], create ? 4 : 3);
                if (result)
                {
                    auto key = Json::array({rva, Read<uint64_t>(row["arguments"], (create ? 2 : 1) * 8)}).dump();
                    if (!failures.contains(key)) continue;
                    auto failure = failures.at(key);
                    Require(result == failure["result"] && after.empty(), "Failed LDAP paging output differs", row);
                    auto label = failure["stage"].get<std::string>();
                    auto cookie = part(before, 5), array = part(before, 10), control = part(before, 7);
                    auto oid = part(before, 8), binary = part(before, 9);
                    if (label == "PARTIALCOOKIE")
                        Require(cookie.size() == 1 && (cookie[0].flags & 2) && part(before, 6).empty(),
                                "Partial LDAP cookie was dereferenced", row);
                    else if (label == "PARTIALARRAY")
                        Require(array.size() == 1 && (array[0].flags & 2) && control.empty(),
                                "Partial LDAP control table was dereferenced", row);
                    else if (label == "PARTIALCONTROL" || limit == 16)
                        Require((label != "PARTIALCONTROL" || !control.empty()) && oid.empty() && binary.empty(),
                                "Partial LDAP control references were followed", row);
                    else if (label == "BADREFERENCES")
                        Require(!oid.empty() && (oid[0].flags & 2) && !binary.empty() && (binary[0].flags & 2),
                                "Invalid LDAP control references lack unreadable flags", row);
                    guarded.insert(label);
                    continue;
                }
                uint64_t page = 0;
                if (create)
                    page = Read<uint64_t>(row["arguments"], 8);
                else
                {
                    auto total = Regions(row["output"], {.parameter = 2});
                    Require(total.size() == 1 && total[0].data.size() == 4, "LDAP page count missing", row);
                    page = Read<uint32_t>(total[0].data);
                }
                auto key = Json::array({create ? "CREATE" : "PARSE", rva, page}).dump();
                if (!expected.contains(key)) continue;
                auto sample = expected.at(key);
                auto cookieBytes = Unhex(sample["cookie"]);
                const auto& controlValues = create ? after : before;
                uint32_t controlIndex = create ? 0 : 1;
                if (create && !Read<uint64_t>(row["arguments"], 16))
                    Require(before.empty(), "Null LDAP cookie has captured input", row);
                else
                {
                    const auto& cookieValues = create ? before : after;
                    auto header = part(cookieValues, 5), binary = part(cookieValues, 6);
                    Require(header.size() == 1 && header[0].data.size() == 16, "LDAP cookie header differs", row);
                    Require(cookieBytes.empty() ? binary.empty()
                                                : binary.size() == 1 && binary[0].original == cookieBytes.size() &&
                                                      binary[0].data == Prefix(cookieBytes, limit),
                            "LDAP cookie bytes differ", row);
                }
                if (create)
                    Require(!part(after, 7).empty() && ldap(row["output"], 2).empty(),
                            "Created LDAP control output differs", row);
                else
                {
                    auto table = part(before, 10);
                    Require(table.size() == 1 && table[0].data.size() == std::min(limit, 24u) &&
                                bool(table[0].flags & 1) == (limit == 16) && !part(before, 7, 0).empty() &&
                                !part(before, 7, 1).empty(),
                            "LDAP parse control table differs", row);
                }
                auto oid = part(controlValues, 8, controlIndex), binary = part(controlValues, 9, controlIndex);
                if (limit == 16)
                    Require(oid.empty() && binary.empty(), "Capped LDAP descriptor references were followed", row);
                else
                {
                    bool wide = name.ends_with('W');
                    auto encoded = Unhex(sample["encoded"]);
                    Require(oid.size() == 1 && oid[0].kind == uint32_t(wide) &&
                                oid[0].data == Encode("1.2.840.113556.1.4.319", wide, true),
                            "LDAP control OID differs", row);
                    Require(binary.size() == 1 && binary[0].original == encoded.size() &&
                                binary[0].data == Prefix(encoded, limit),
                            "LDAP encoded control differs", row);
                }
                if (page == 5000 && !context.Optional(0).empty() && !seen.contains(key))
                {
                    auto detail = capture.Details(row);
                    details.push_back({{"family", "ldap-control"},
                                       {"limit", limit},
                                       {"call", detail},
                                       {"parameter", create ? 4 : 1}});
                    details.push_back(
                        {{"family", "ldap-berval"}, {"limit", limit}, {"call", detail}, {"parameter", create ? 2 : 3}});
                }
                seen.insert(key);
            }
            std::set<std::string> expectedKeys;
            for (const auto& [key, row] : expected)
                expectedKeys.insert(key);
            Require(seen == expectedKeys && guarded == expectedGuards && freed == expectedFreed,
                    "LDAP paging coverage differs", rows);
        }, 60);
    }
    if (!context.Optional(0).empty()) WriteJson(context.Optional(0), details);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, LdapControl); }

#else
#error Select a native test target.
#endif
