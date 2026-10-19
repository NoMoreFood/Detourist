#include "ManagedMetadata.h"
#include "Protocol.h"
#include <wrl/client.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <stdexcept>

namespace Detourist
{
using Microsoft::WRL::ComPtr;
constexpr uint32_t IlPrefixOpcode = 0xFE;
constexpr uint32_t IlTwoByteOpcodeBase = 0x100;
constexpr uint32_t IlOperandSizeMask = 15u;
constexpr uint32_t IlOperandBranchFlag = 16u;
constexpr uint32_t IlOperandSwitchFlag = 32u;
constexpr uint32_t IlTinyDefaultMaxStack = 8;
constexpr uint32_t IlHeaderFormatMask = 3;
constexpr uint32_t IlFatHeaderSizeShift = 12;
constexpr uint32_t IlFatHeaderSizeScale = 4;
constexpr uint32_t IlFatHeaderMinBytes = 12;
constexpr uint32_t IlFatHeaderFlagsMask = 0xFFF;
constexpr size_t IlFatHeaderMaxStackOffset = 2;
constexpr size_t IlFatHeaderCodeSizeOffset = 4;
constexpr size_t IlFatHeaderLocalsOffset = 8;
constexpr uint32_t IlFatHeaderDwords = 3;
constexpr uint32_t IlMaxStackLimit = 65510;
constexpr uint32_t IlAddedMaxStack = 24;
constexpr uint32_t IlShortBranchOpcodeDelta = 13;
constexpr uint32_t IlSectionAlignMask = 3u;
constexpr uint32_t IlSectionHeaderBytes = 4;
constexpr uint32_t IlSectionSizeShift = 8;
constexpr uint32_t IlMaxFatSectionBytes = 0xFFFFFF;
constexpr uint32_t MaxSignatureDepth = 32;
constexpr uint32_t MaxGenericArguments = 256;
constexpr uint32_t MaxArrayRank = 32;
constexpr uint32_t MaxMethodParameters = 1024;
constexpr uint32_t MaxLocalVariables = 65535;
enum IlOpcode
{
#define OPDEF(code, text, pop, push, args, kind, size, first, second, flow) code,
#include <opcode.def>
#undef OPDEF
    IlOpcodeCount
};

constexpr BYTE IlOperandFlags[] =
{
#define InlineNone 0
#define ShortInlineVar 1
#define InlineVar 2
#define ShortInlineI 1
#define InlineI 4
#define InlineI8 8
#define ShortInlineR 4
#define InlineR 8
#define ShortInlineBrTarget (1 | 16)
#define InlineBrTarget (4 | 16)
#define InlineMethod 4
#define InlineField 4
#define InlineType 4
#define InlineString 4
#define InlineSig 4
#define InlineRVA 4
#define InlineTok 4
#define InlineSwitch 32
#define OPDEF(code, text, pop, push, args, kind, size, first, second, flow) args,
#include <opcode.def>
#undef OPDEF
#undef InlineNone
#undef ShortInlineVar
#undef InlineVar
#undef ShortInlineI
#undef InlineI
#undef InlineI8
#undef ShortInlineR
#undef InlineR
#undef ShortInlineBrTarget
#undef InlineBrTarget
#undef InlineMethod
#undef InlineField
#undef InlineType
#undef InlineString
#undef InlineSig
#undef InlineRVA
#undef InlineTok
#undef InlineSwitch
};

class IlWriter
{
public:
    std::vector<BYTE> bytes;
    template<class T> void Data(T value)
    {
        auto start = bytes.size();
        bytes.resize(start + sizeof(value));
        memcpy(bytes.data() + start, &value, sizeof(value));
    }
    void Op(uint32_t opcode)
    {
        if (opcode >= IlTwoByteOpcodeBase) Data<BYTE>(static_cast<BYTE>(IlPrefixOpcode));
        Data<BYTE>(static_cast<BYTE>(opcode));
    }
    void Integer(uint32_t value) { Op(CEE_LDC_I4); Data(value); }
    void Pointer(uint64_t value) { Op(CEE_LDC_I8); Data(value); Op(CEE_CONV_I); }
    void Variable(uint32_t opcode, uint32_t value) { Op(opcode); Data(static_cast<uint16_t>(value)); }
    size_t Branch(uint32_t opcode)
    {
        Op(opcode);
        auto offset = bytes.size();
        Data<int32_t>(0);
        return offset;
    }
    void Patch(size_t offset, size_t target)
    {
        auto distance = static_cast<int32_t>(target - offset - sizeof(int32_t));
        memcpy(bytes.data() + offset, &distance, sizeof(distance));
    }
};

void SignatureNumber(std::vector<BYTE>& output, uint32_t value)
{
    BYTE data[4];
    auto size = CorSigCompressData(value, data);
    output.insert(output.end(), data, data + size);
}

struct InstrumentedType
{
    std::vector<BYTE> signature, valueSignature, elementSignature;
    CorElementType element = ELEMENT_TYPE_END;
    uint32_t bytes = 0;
    uint32_t pin = UINT32_MAX, objectPin = UINT32_MAX;
    mdTypeSpec sizeToken = 0, elementToken = 0;
    bool byReference = false, reference = false, runtimeArray = false;
};

class InstrumentationSignature : public ManagedSignatureCursor
{
public:
    using ManagedSignatureCursor::ManagedSignatureCursor;
    InstrumentedType Type(uint32_t depth = 0)
    {
        if (depth > MaxSignatureDepth) throw std::runtime_error("CLR signature nesting exceeded.");
        auto start = Position();
        InstrumentedType type;
        type.element = static_cast<CorElementType>(Byte());
        switch (type.element)
        {
        case ELEMENT_TYPE_CMOD_OPT:
        case ELEMENT_TYPE_CMOD_REQD:
            Number();
            type = Type(depth + 1);
            break;
        case ELEMENT_TYPE_BYREF:
            type = Type(depth + 1);
            type.byReference = true;
            break;
        case ELEMENT_TYPE_PTR:
            Type(depth + 1);
            type.bytes = sizeof(void*);
            break;
        case ELEMENT_TYPE_CLASS:
        case ELEMENT_TYPE_VALUETYPE:
            Number();
            type.reference = type.element == ELEMENT_TYPE_CLASS;
            type.bytes = type.reference ? sizeof(void*) : 0;
            break;
        case ELEMENT_TYPE_VAR:
        case ELEMENT_TYPE_MVAR:
            Number();
            break;
        case ELEMENT_TYPE_GENERICINST:
        {
            auto category = Byte();
            Number();
            auto count = Number();
            if (count > MaxGenericArguments) throw std::runtime_error("Invalid CLR generic signature.");
            for (uint32_t index = 0; index < count; ++index) Type(depth + 1);
            type.reference = category == ELEMENT_TYPE_CLASS;
            type.bytes = type.reference ? sizeof(void*) : 0;
            break;
        }
        case ELEMENT_TYPE_SZARRAY:
            type.elementSignature = Type(depth + 1).signature;
            type.reference = true;
            type.bytes = sizeof(void*);
            break;
        case ELEMENT_TYPE_ARRAY:
        {
            Type(depth + 1);
            auto rank = Number(), sizes = Number();
            if (rank > MaxArrayRank || sizes > MaxArrayRank) throw std::runtime_error("Invalid CLR array signature.");
            for (uint32_t index = 0; index < sizes; ++index) Number();
            auto bounds = Number();
            if (bounds > MaxArrayRank) throw std::runtime_error("Invalid CLR array signature.");
            for (uint32_t index = 0; index < bounds; ++index) Number();
            type.reference = true;
            type.runtimeArray = true;
            type.bytes = sizeof(void*);
            break;
        }
        case ELEMENT_TYPE_FNPTR:
        {
            auto convention = Number();
            if (convention & IMAGE_CEE_CS_CALLCONV_GENERIC) Number();
            auto count = Number();
            if (count > MaxMethodParameters) throw std::runtime_error("Invalid CLR function signature.");
            Type(depth + 1);
            for (uint32_t index = 0; index < count; ++index) Type(depth + 1);
            type.bytes = sizeof(void*);
            break;
        }
        case ELEMENT_TYPE_STRING:
        case ELEMENT_TYPE_OBJECT:
            type.reference = true;
            type.bytes = sizeof(void*);
            break;
        case ELEMENT_TYPE_TYPEDBYREF: type.bytes = 2 * sizeof(void*); break;
        case ELEMENT_TYPE_VOID: break;
        default:
            type.bytes = ManagedScalarBytes(type.element);
            if (!type.bytes) throw std::runtime_error("Unsupported CLR signature.");
            break;
        }
        type.signature.assign(start, Position());
        if (type.valueSignature.empty()) type.valueSignature = type.signature;
        return type;
    }
};

struct IlInstruction
{
    uint32_t oldOffset, newOffset = 0, opcode;
    std::vector<BYTE> operand;
    std::vector<uint32_t> targets;
};

template<class T> T IlRead(std::span<const BYTE> input, size_t offset)
{
    if (offset > input.size() || sizeof(T) > input.size() - offset)
        throw std::runtime_error("Incomplete CLR method body.");
    T value;
    memcpy(&value, input.data() + offset, sizeof(value));
    return value;
}

HRESULT InstrumentManagedMethod(ICorProfilerInfo* profiler, ModuleID coreLibrary, ManagedMethod* method,
    std::span<const BYTE> original, ULONG stringLengthOffset, ULONG stringDataOffset,
    ManagedCallback callback, ManagedSnapshotGuard guard, std::vector<BYTE>& output)
{
    try
    {
        // Parse original branches and exception regions before expanding the method body.
        uint32_t codeOffset = 1, codeSize = 0, localsToken = 0, flags = 0, maxStack = IlTinyDefaultMaxStack;
        auto first = IlRead<BYTE>(original, 0);
        if ((first & IlHeaderFormatMask) == CorILMethod_TinyFormat) codeSize = first >> 2;
        else if ((first & IlHeaderFormatMask) == CorILMethod_FatFormat)
        {
            auto header = IlRead<uint16_t>(original, 0);
            codeOffset = (header >> IlFatHeaderSizeShift) * IlFatHeaderSizeScale;
            if (codeOffset < IlFatHeaderMinBytes) return COR_E_INVALIDPROGRAM;
            flags = header & IlFatHeaderFlagsMask;
            maxStack = IlRead<uint16_t>(original, IlFatHeaderMaxStackOffset);
            codeSize = IlRead<uint32_t>(original, IlFatHeaderCodeSizeOffset);
            localsToken = IlRead<uint32_t>(original, IlFatHeaderLocalsOffset);
        }
        else return COR_E_INVALIDPROGRAM;
        if (codeOffset > original.size() || codeSize > original.size() - codeOffset || maxStack > IlMaxStackLimit)
            return COR_E_INVALIDPROGRAM;
        auto code = original.subspan(codeOffset, codeSize);
        std::vector<IlInstruction> instructions;
        for (uint32_t offset = 0; offset < codeSize;)
        {
            IlInstruction instruction{};
            instruction.oldOffset = offset;
            instruction.opcode = IlRead<BYTE>(code, offset++);
            if (instruction.opcode == IlPrefixOpcode)
                instruction.opcode = IlTwoByteOpcodeBase + IlRead<BYTE>(code, offset++);
            if (instruction.opcode >= std::size(IlOperandFlags)) return COR_E_INVALIDPROGRAM;
            auto operandFlags = IlOperandFlags[instruction.opcode];
            auto bytes = operandFlags & IlOperandSizeMask;
            if (operandFlags & IlOperandSwitchFlag)
            {
                auto count = IlRead<uint32_t>(code, offset);
                if (count > (codeSize - offset - 4) / 4) return COR_E_INVALIDPROGRAM;
                auto end = offset + 4 + count * 4;
                for (uint32_t index = 0; index < count; ++index)
                    instruction.targets.push_back(end + IlRead<int32_t>(code, offset + 4 + index * 4));
                bytes = 4 + count * 4;
            }
            else if (operandFlags & IlOperandBranchFlag)
            {
                auto relative = bytes == 1 ? IlRead<int8_t>(code, offset) : IlRead<int32_t>(code, offset);
                instruction.targets.push_back(offset + bytes + relative);
                if (bytes == 1)
                    instruction.opcode = instruction.opcode == CEE_LEAVE_S ? CEE_LEAVE :
                        instruction.opcode + IlShortBranchOpcodeDelta;
            }
            if (bytes > codeSize - offset) return COR_E_INVALIDPROGRAM;
            instruction.operand.assign(code.begin() + offset, code.begin() + offset + bytes);
            offset += bytes;
            instructions.push_back(std::move(instruction));
        }
        std::vector<IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT> clauses;
        if (flags & CorILMethod_MoreSects)
        {
            auto section = (codeOffset + codeSize + IlSectionAlignMask) & ~IlSectionAlignMask;
            bool more = true;
            while (more)
            {
                auto kind = IlRead<BYTE>(original, section);
                auto fat = (kind & CorILMethod_Sect_FatFormat) != 0;
                auto size = fat ? IlRead<uint32_t>(original, section) >> IlSectionSizeShift :
                    IlRead<BYTE>(original, section + 1);
                if (size < IlSectionHeaderBytes || section > original.size() || size > original.size() - section ||
                    (kind & CorILMethod_Sect_KindMask) != CorILMethod_Sect_EHTable) return COR_E_INVALIDPROGRAM;
                auto clauseSize = fat ? sizeof(IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT) :
                    sizeof(IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL);
                if ((size - IlSectionHeaderBytes) % clauseSize) return COR_E_INVALIDPROGRAM;
                for (uint32_t position = IlSectionHeaderBytes; position < size;
                    position += static_cast<uint32_t>(clauseSize))
                {
                    IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT clause{};
                    if (fat) clause = IlRead<IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT>(original, section + position);
                    else
                    {
                        auto compact = IlRead<IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL>(original, section + position);
                        clause.Flags = static_cast<CorExceptionFlag>(compact.Flags);
                        clause.TryOffset = compact.TryOffset;
                        clause.TryLength = compact.TryLength;
                        clause.HandlerOffset = compact.HandlerOffset;
                        clause.HandlerLength = compact.HandlerLength;
                        clause.ClassToken = compact.ClassToken;
                    }
                    clauses.push_back(clause);
                }
                more = (kind & CorILMethod_Sect_MoreSects) != 0;
                section = (section + size + IlSectionAlignMask) & ~IlSectionAlignMask;
            }
        }

        // Preserve signature types so generic and value-type sizes are resolved by this JIT compilation.
        ComPtr<IMetaDataImport2> metadata;
        auto result = profiler->GetModuleMetaData(method->module, ofRead | ofWrite, IID_IMetaDataImport2,
            reinterpret_cast<IUnknown**>(metadata.GetAddressOf()));
        if (FAILED(result)) return result;
        ComPtr<IMetaDataEmit> emit;
        if (FAILED(result = metadata->QueryInterface(IID_IMetaDataEmit,
            reinterpret_cast<void**>(emit.GetAddressOf())))) return result;
        PCCOR_SIGNATURE signature = nullptr;
        ULONG signatureBytes = 0;
        mdTypeDef declaringType = 0;
        DWORD attributes = 0;
        if (FAILED(result = metadata->GetMethodProps(method->token, &declaringType, nullptr, 0, nullptr,
            &attributes, &signature, &signatureBytes, nullptr, nullptr))) return result;
        InstrumentationSignature reader({signature, signatureBytes});
        auto convention = reader.Number();
        if ((convention & IMAGE_CEE_CS_CALLCONV_MASK) == IMAGE_CEE_CS_CALLCONV_VARARG) return E_NOTIMPL;
        if (convention & IMAGE_CEE_CS_CALLCONV_GENERIC) reader.Number();
        auto parameterCount = reader.Number();
        if (parameterCount > MaxMethodParameters) return E_NOTIMPL;
        auto returnType = reader.Type();
        bool hasResult = returnType.element != ELEMENT_TYPE_VOID;
        std::vector<InstrumentedType> types;
        if (!(attributes & mdStatic))
        {
            mdToken baseType = 0;
            metadata->GetTypeDefProps(declaringType, nullptr, 0, nullptr, nullptr, &baseType);
            bool valueType = IsValueTypeBase(metadata.Get(), baseType);
            HCORENUM enumeration = nullptr;
            mdGenericParam generics[MaxGenericArguments];
            ULONG genericCount = 0;
            result = metadata->EnumGenericParams(&enumeration, declaringType, generics, _countof(generics),
                &genericCount);
            metadata->CloseEnum(enumeration);
            if (FAILED(result) || genericCount == _countof(generics)) return E_NOTIMPL;
            std::vector<BYTE> selfSignature;
            if (valueType) selfSignature.push_back(ELEMENT_TYPE_BYREF);
            if (genericCount) selfSignature.push_back(ELEMENT_TYPE_GENERICINST);
            selfSignature.push_back(static_cast<BYTE>(valueType ? ELEMENT_TYPE_VALUETYPE : ELEMENT_TYPE_CLASS));
            BYTE tokenBytes[4];
            auto tokenSize = CorSigCompressToken(declaringType, tokenBytes);
            selfSignature.insert(selfSignature.end(), tokenBytes, tokenBytes + tokenSize);
            if (genericCount)
            {
                SignatureNumber(selfSignature, genericCount);
                for (ULONG index = 0; index < genericCount; ++index)
                {
                    selfSignature.push_back(ELEMENT_TYPE_VAR);
                    SignatureNumber(selfSignature, index);
                }
            }
            types.push_back(InstrumentationSignature(selfSignature).Type());
        }
        for (uint32_t index = 0; index < parameterCount; ++index) types.push_back(reader.Type());
        types.resize(std::min<size_t>(types.size(), MaximumArguments));
        auto argumentCount = static_cast<uint32_t>(types.size());
        if (hasResult) types.push_back(returnType);
        for (size_t index = 0; index < types.size(); ++index)
        {
            auto description = index == argumentCount ? &method->result :
                index < method->arguments.size() ? &method->arguments[index] : nullptr;
            if (description && description->arrayRank == UINT32_MAX) types[index].runtimeArray = true;
        }

        // Import public helpers from the loaded core library for arrays whose element type is not in the signature.
        mdToken arrayAddress = 0, arrayLength = 0;
        if (std::any_of(types.begin(), types.end(), [](const auto& type) { return type.runtimeArray; }))
        {
            ComPtr<IMetaDataImport> core;
            if (!coreLibrary) return E_NOTIMPL;
            if (FAILED(result = profiler->GetModuleMetaData(coreLibrary, ofRead, IID_IMetaDataImport,
                reinterpret_cast<IUnknown**>(core.GetAddressOf())))) return result;
            mdTypeDef arrayType = 0, marshalType = 0;
            if (FAILED(result = core->FindTypeDefByName(L"System.Array", 0, &arrayType)) ||
                FAILED(result = core->FindTypeDefByName(L"System.Runtime.InteropServices.Marshal", 0, &marshalType)))
                return result;
            std::vector<BYTE> addressSignature{IMAGE_CEE_CS_CALLCONV_DEFAULT, 2, ELEMENT_TYPE_I, ELEMENT_TYPE_CLASS};
            BYTE encoded[4];
            auto encodedBytes = CorSigCompressToken(arrayType, encoded);
            addressSignature.insert(addressSignature.end(), encoded, encoded + encodedBytes);
            addressSignature.push_back(ELEMENT_TYPE_I4);
            constexpr BYTE lengthSignature[] = {IMAGE_CEE_CS_CALLCONV_HASTHIS, 0, ELEMENT_TYPE_I8};
            if (FAILED(result = core->FindMethod(marshalType, L"UnsafeAddrOfPinnedArrayElement",
                addressSignature.data(), static_cast<ULONG>(addressSignature.size()), &arrayAddress)) ||
                FAILED(result = core->FindMethod(arrayType, L"get_LongLength", lengthSignature,
                    sizeof(lengthSignature), &arrayLength))) return result;
            if (coreLibrary != method->module)
            {
                ComPtr<IMetaDataAssemblyImport> source;
                ComPtr<IMetaDataAssemblyEmit> destination;
                if (FAILED(result = core->QueryInterface(IID_IMetaDataAssemblyImport,
                    reinterpret_cast<void**>(source.GetAddressOf()))) ||
                    FAILED(result = emit->QueryInterface(IID_IMetaDataAssemblyEmit,
                        reinterpret_cast<void**>(destination.GetAddressOf())))) return result;
                for (auto [type, member] : {std::pair{marshalType, &arrayAddress}, std::pair{arrayType, &arrayLength}})
                {
                    mdTypeRef parent = 0;
                    mdMemberRef imported = 0;
                    if (FAILED(result = emit->DefineImportType(source.Get(), nullptr, 0, core.Get(), type,
                        destination.Get(), &parent)) ||
                        FAILED(result = emit->DefineImportMember(source.Get(), nullptr, 0, core.Get(), *member,
                            destination.Get(), parent, &imported))) return result;
                    *member = imported;
                }
            }
        }
        std::vector<BYTE> oldLocals;
        uint32_t localCount = 0;
        if (localsToken)
        {
            PCCOR_SIGNATURE locals = nullptr;
            ULONG localsBytes = 0;
            if (FAILED(result = metadata->GetSigFromToken(localsToken, &locals, &localsBytes))) return result;
            InstrumentationSignature localReader({locals, localsBytes});
            if (localReader.Byte() != IMAGE_CEE_CS_CALLCONV_LOCAL_SIG) return COR_E_INVALIDPROGRAM;
            localCount = localReader.Number();
            oldLocals.assign(localReader.Position(), locals + localsBytes);
        }
        auto regionLocal = localCount++;
        auto resultLocal = hasResult ? localCount++ : UINT32_MAX;
        std::vector<BYTE> additionalLocals{ELEMENT_TYPE_I};
        if (hasResult) additionalLocals.insert(additionalLocals.end(), returnType.signature.begin(),
            returnType.signature.end());
        for (auto& type : types)
        {
            if (type.byReference)
            {
                type.pin = localCount++;
                additionalLocals.push_back(ELEMENT_TYPE_PINNED);
                additionalLocals.insert(additionalLocals.end(), type.signature.begin(), type.signature.end());
            }
            if (type.reference)
            {
                type.objectPin = localCount++;
                additionalLocals.push_back(ELEMENT_TYPE_PINNED);
                additionalLocals.push_back(ELEMENT_TYPE_OBJECT);
            }
            if (!type.bytes && type.element != ELEMENT_TYPE_VOID)
                if (FAILED(result = emit->GetTokenFromTypeSpec(type.valueSignature.data(),
                    static_cast<ULONG>(type.valueSignature.size()), &type.sizeToken))) return result;
            if (type.element == ELEMENT_TYPE_SZARRAY)
                if (FAILED(result = emit->GetTokenFromTypeSpec(type.elementSignature.data(),
                    static_cast<ULONG>(type.elementSignature.size()), &type.elementToken))) return result;
        }
        if (localCount > MaxLocalVariables) return E_NOTIMPL;
        std::vector<BYTE> locals{IMAGE_CEE_CS_CALLCONV_LOCAL_SIG};
        SignatureNumber(locals, localCount);
        locals.insert(locals.end(), oldLocals.begin(), oldLocals.end());
        locals.insert(locals.end(), additionalLocals.begin(), additionalLocals.end());
        mdSignature newLocals = 0, callbackSignature = 0, guardSignature = 0;
        constexpr BYTE callbackTypes[] = {IMAGE_CEE_CS_CALLCONV_STDCALL, 3, ELEMENT_TYPE_VOID,
            ELEMENT_TYPE_I, ELEMENT_TYPE_I, ELEMENT_TYPE_U4};
        constexpr BYTE guardTypes[] = {IMAGE_CEE_CS_CALLCONV_STDCALL, 1, ELEMENT_TYPE_I4, ELEMENT_TYPE_I4};
        if (FAILED(result = emit->GetTokenFromSig(locals.data(), static_cast<ULONG>(locals.size()), &newLocals)) ||
            FAILED(result = emit->GetTokenFromSig(callbackTypes, sizeof(callbackTypes), &callbackSignature)) ||
            FAILED(result = emit->GetTokenFromSig(guardTypes, sizeof(guardTypes), &guardSignature)))
            return result;

        // Pins are cleared after each snapshot; the target's own references remain movable between calls.
        IlWriter body;
        std::vector<IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT> snapshotClauses;
        auto clearPins = [&]()
        {
            for (const auto& type : types)
            {
                if (type.pin != UINT32_MAX)
                {
                    body.Integer(0);
                    body.Op(CEE_CONV_U);
                    body.Variable(CEE_STLOC, type.pin);
                }
                if (type.objectPin != UINT32_MAX)
                {
                    body.Op(CEE_LDNULL);
                    body.Variable(CEE_STLOC, type.objectPin);
                }
            }
        };
        auto capture = [&](ManagedCallPhase phase)
        {
            // Managed helpers can themselves be instrumented; suppress their snapshots until this one completes.
            body.Integer(TRUE);
            body.Pointer(reinterpret_cast<uintptr_t>(guard));
            body.Op(CEE_CALLI);
            body.Data(guardSignature);
            auto nestedSnapshot = body.Branch(CEE_BRFALSE);
            IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT cleanup{};
            cleanup.Flags = COR_ILEXCEPTION_CLAUSE_FINALLY;
            cleanup.TryOffset = static_cast<uint32_t>(body.bytes.size());
            body.Variable(CEE_LDLOC, regionLocal);
            body.Integer(0);
            body.Integer(static_cast<uint32_t>(std::max<size_t>(1, types.size()) * sizeof(ManagedArgument)));
            body.Op(CEE_INITBLK);
            auto count = phase == ManagedCallPhase::Enter || phase == ManagedCallPhase::Tailcall ?
                argumentCount : static_cast<uint32_t>(types.size());
            for (uint32_t index = 0; index < count; ++index)
            {
                auto& type = types[index];
                auto load = [&]()
                {
                    body.Variable(index < argumentCount ? CEE_LDARG : CEE_LDLOC,
                        index < argumentCount ? index : resultLocal);
                };
                auto object = [&]() { body.Variable(CEE_LDLOC, type.objectPin); };
                auto size = [&]()
                {
                    if (type.bytes) body.Integer(type.bytes);
                    else { body.Op(CEE_SIZEOF); body.Data(type.sizeToken); }
                };
                auto store = [&](size_t field, const std::function<void()>& value)
                {
                    body.Variable(CEE_LDLOC, regionLocal);
                    body.Integer(index * static_cast<uint32_t>(sizeof(ManagedArgument)) +
                        static_cast<uint32_t>(field));
                    body.Op(CEE_ADD);
                    value();
                    body.Op(CEE_CONV_U);
                    body.Op(CEE_STIND_I);
                };
                if (type.pin != UINT32_MAX)
                {
                    load();
                    body.Variable(CEE_STLOC, type.pin);
                }
                store(offsetof(ManagedArgument, address), [&]()
                {
                    body.Variable(index < argumentCount ? CEE_LDARGA : CEE_LDLOCA,
                        index < argumentCount ? index : resultLocal);
                });
                store(offsetof(ManagedArgument, bytes), [&]()
                {
                    if (type.byReference) body.Integer(sizeof(void*));
                    else size();
                });
                size_t nullReference = 0;
                if (type.byReference)
                {
                    store(offsetof(ManagedArgument, indirect), load);
                    store(offsetof(ManagedArgument, indirectBytes), size);
                    load();
                    nullReference = body.Branch(CEE_BRFALSE);
                }
                if (type.objectPin != UINT32_MAX)
                {
                    load();
                    if (type.byReference) body.Op(CEE_LDIND_REF);
                    body.Variable(CEE_STLOC, type.objectPin);
                }
                if (type.element == ELEMENT_TYPE_STRING || type.element == ELEMENT_TYPE_SZARRAY || type.runtimeArray)
                {
                    object();
                    auto nullObject = body.Branch(CEE_BRFALSE);
                    if (type.element == ELEMENT_TYPE_STRING)
                    {
                        store(offsetof(ManagedArgument, buffer), [&]()
                        {
                            object(); body.Op(CEE_CONV_U); body.Integer(stringDataOffset); body.Op(CEE_ADD);
                        });
                        store(offsetof(ManagedArgument, bufferBytes), [&]()
                        {
                            object(); body.Op(CEE_CONV_U); body.Integer(stringLengthOffset); body.Op(CEE_ADD);
                            body.Op(CEE_LDIND_U4); body.Op(CEE_CONV_U); body.Integer(2); body.Op(CEE_MUL);
                        });
                    }
                    else if (type.runtimeArray)
                    {
                        // Address arithmetic gives the stride without reading an element, even for an empty array.
                        auto field = [&](size_t offset)
                        {
                            body.Variable(CEE_LDLOC, regionLocal);
                            body.Integer(index * static_cast<uint32_t>(sizeof(ManagedArgument)) +
                                static_cast<uint32_t>(offset));
                            body.Op(CEE_ADD); body.Op(CEE_LDIND_I);
                        };
                        store(offsetof(ManagedArgument, buffer), [&]()
                        {
                            object(); body.Integer(0); body.Op(CEE_CALL); body.Data(arrayAddress);
                        });
                        store(offsetof(ManagedArgument, elementBytes), [&]()
                        {
                            object(); body.Integer(1); body.Op(CEE_CALL); body.Data(arrayAddress);
                            field(offsetof(ManagedArgument, buffer)); body.Op(CEE_SUB);
                        });
                        store(offsetof(ManagedArgument, bufferBytes), [&]()
                        {
                            object(); body.Op(CEE_CALL); body.Data(arrayLength); body.Op(CEE_CONV_U);
                            field(offsetof(ManagedArgument, elementBytes)); body.Op(CEE_MUL);
                        });
                    }
                    else
                    {
                        store(offsetof(ManagedArgument, elementBytes), [&]()
                        {
                            body.Op(CEE_SIZEOF); body.Data(type.elementToken);
                        });
                        store(offsetof(ManagedArgument, bufferBytes), [&]()
                        {
                            object(); body.Op(CEE_LDLEN); body.Op(CEE_SIZEOF); body.Data(type.elementToken);
                            body.Op(CEE_MUL);
                        });
                        object(); body.Op(CEE_LDLEN);
                        auto emptyArray = body.Branch(CEE_BRFALSE);
                        store(offsetof(ManagedArgument, buffer), [&]()
                        {
                            object(); body.Integer(0); body.Op(CEE_READONLY); body.Op(CEE_LDELEMA);
                            body.Data(type.elementToken);
                        });
                        body.Patch(emptyArray, body.bytes.size());
                    }
                    body.Patch(nullObject, body.bytes.size());
                }
                if (nullReference) body.Patch(nullReference, body.bytes.size());
            }
            body.Pointer(reinterpret_cast<uintptr_t>(method));
            body.Variable(CEE_LDLOC, regionLocal);
            body.Integer(static_cast<uint32_t>(phase));
            body.Pointer(reinterpret_cast<uintptr_t>(callback));
            body.Op(CEE_CALLI);
            body.Data(callbackSignature);
            auto completed = body.Branch(CEE_LEAVE);
            cleanup.HandlerOffset = static_cast<uint32_t>(body.bytes.size());
            cleanup.TryLength = cleanup.HandlerOffset - cleanup.TryOffset;
            clearPins();
            body.Integer(FALSE);
            body.Pointer(reinterpret_cast<uintptr_t>(guard));
            body.Op(CEE_CALLI);
            body.Data(guardSignature);
            body.Op(CEE_POP);
            body.Op(CEE_ENDFINALLY);
            cleanup.HandlerLength = static_cast<uint32_t>(body.bytes.size()) - cleanup.HandlerOffset;
            snapshotClauses.push_back(cleanup);
            body.Patch(completed, body.bytes.size());
            body.Patch(nestedSnapshot, body.bytes.size());
        };
        clearPins();
        auto regionBytes = static_cast<uint32_t>(std::max<size_t>(1, types.size()) * sizeof(ManagedArgument));
        body.Integer(regionBytes);
        body.Op(CEE_LOCALLOC);
        body.Variable(CEE_STLOC, regionLocal);
        capture(ManagedCallPhase::Enter);

        std::vector<uint32_t> offsets(codeSize + 1, UINT32_MAX);
        for (auto& instruction : instructions)
        {
            instruction.newOffset = static_cast<uint32_t>(body.bytes.size());
            offsets[instruction.oldOffset] = instruction.newOffset;
            if (instruction.opcode == CEE_RET)
            {
                if (hasResult) body.Variable(CEE_STLOC, resultLocal);
                capture(ManagedCallPhase::Leave);
                if (hasResult) body.Variable(CEE_LDLOC, resultLocal);
            }
            else if (instruction.opcode == CEE_JMP) capture(ManagedCallPhase::Tailcall);
            if (instruction.opcode == CEE_TAILCALL) body.Op(CEE_NOP);
            else
            {
                body.Op(instruction.opcode);
                if (instruction.opcode == CEE_SWITCH)
                {
                    body.Data(static_cast<uint32_t>(instruction.targets.size()));
                    for (size_t index = 0; index < instruction.targets.size(); ++index) body.Data<int32_t>(0);
                }
                else if (!instruction.targets.empty()) body.Data<int32_t>(0);
                else body.bytes.insert(body.bytes.end(), instruction.operand.begin(), instruction.operand.end());
            }
        }
        offsets[codeSize] = static_cast<uint32_t>(body.bytes.size());
        auto mapped = [&](uint32_t offset)
        {
            if (offset >= offsets.size() || offsets[offset] == UINT32_MAX)
                throw std::runtime_error("Invalid CLR branch or exception boundary.");
            return offsets[offset];
        };
        for (const auto& instruction : instructions)
        {
            if (instruction.targets.empty()) continue;
            auto position = instruction.newOffset + (instruction.opcode >= IlTwoByteOpcodeBase ? 2 : 1);
            auto end = position + 4;
            if (instruction.opcode == CEE_SWITCH)
            {
                position += 4;
                end = position + static_cast<uint32_t>(instruction.targets.size()) * 4;
            }
            for (auto target : instruction.targets)
            {
                auto relative = static_cast<int32_t>(mapped(target) - end);
                memcpy(body.bytes.data() + position, &relative, sizeof(relative));
                position += 4;
            }
        }
        for (auto& clause : clauses)
        {
            auto tryEnd = mapped(clause.TryOffset + clause.TryLength);
            auto handlerEnd = mapped(clause.HandlerOffset + clause.HandlerLength);
            clause.TryOffset = mapped(clause.TryOffset);
            clause.TryLength = tryEnd - clause.TryOffset;
            clause.HandlerOffset = mapped(clause.HandlerOffset);
            clause.HandlerLength = handlerEnd - clause.HandlerOffset;
            if (clause.Flags & COR_ILEXCEPTION_CLAUSE_FILTER) clause.FilterOffset = mapped(clause.FilterOffset);
        }
        clauses.insert(clauses.begin(), snapshotClauses.begin(), snapshotClauses.end());
        IlWriter header;
        header.Data<uint16_t>(static_cast<uint16_t>((IlFatHeaderDwords << IlFatHeaderSizeShift) |
            CorILMethod_FatFormat | (flags & CorILMethod_InitLocals) |
            (clauses.empty() ? 0 : CorILMethod_MoreSects)));
        header.Data<uint16_t>(static_cast<uint16_t>(maxStack + IlAddedMaxStack));
        header.Data(static_cast<uint32_t>(body.bytes.size()));
        header.Data(newLocals);
        header.bytes.insert(header.bytes.end(), body.bytes.begin(), body.bytes.end());
        if (!clauses.empty())
        {
            while (header.bytes.size() & IlSectionAlignMask) header.bytes.push_back(0);
            auto bytes = static_cast<uint32_t>(IlSectionHeaderBytes + clauses.size() * sizeof(clauses[0]));
            if (bytes > IlMaxFatSectionBytes) return E_NOTIMPL;
            header.Data((bytes << IlSectionSizeShift) | CorILMethod_Sect_EHTable | CorILMethod_Sect_FatFormat);
            for (const auto& clause : clauses) header.Data(clause);
        }
        output = std::move(header.bytes);
        method->instrumentedArguments = argumentCount;
        return S_OK;
    }
    catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
    catch (...) { return COR_E_INVALIDPROGRAM; }
}
}
