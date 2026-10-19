#pragma once
#include <windows.h>
#include <cor.h>
#include <corprof.h>
#include <map>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>
#include <wrl/client.h>

namespace Detourist
{
bool IsValueTypeBase(IMetaDataImport* metadata, mdToken base);
uint32_t ManagedScalarBytes(CorElementType element);

// Both metadata layout and IL instrumentation consume ECMA-335 compressed signature integers.
class ManagedSignatureCursor
{
public:
    explicit ManagedSignatureCursor(std::span<const BYTE> bytes) : next_(bytes.data()), end_(next_ + bytes.size()) {}
    const BYTE* Position() const { return next_; }
    uint32_t Byte()
    {
        if (next_ == end_) throw std::runtime_error("Incomplete managed signature.");
        return *next_++;
    }
    uint32_t Number()
    {
        auto first = Byte();
        if (!(first & 0x80)) return first;
        if ((first & 0xC0) == 0x80) return ((first & 0x3F) << 8) | Byte();
        if ((first & 0xE0) != 0xC0) throw std::runtime_error("Invalid managed signature.");
        uint32_t value = (first & 0x1F) << 24;
        value |= Byte() << 16;
        value |= Byte() << 8;
        return value | Byte();
    }
private:
    const BYTE* next_;
    const BYTE* end_;
};

struct ManagedType
{
    CorElementType element = ELEMENT_TYPE_END;
    uint32_t bytes = 0;
    uint32_t elementBytes = 0;
    bool byReference = false;
    std::wstring name;
    uint32_t referencedBytes = 0;
    ClassID identity = 0;
    ClassID elementIdentity = 0;
    // UINT32_MAX obtains System.Array's rank from the observed object.
    uint32_t arrayRank = 0;
};

class ManagedClasses
{
public:
    void Observe(ICorProfilerInfo2* profiler, ClassID type);
    void Forget(ClassID type);
    void ObserveModule(ICorProfilerInfo2* profiler, ModuleID module);
    void ForgetModule(ModuleID module);
    ClassID Resolve(ICorProfilerInfo2* profiler, ModuleID module, mdToken token,
        std::span<const ClassID> arguments);
    ClassID Primitive(const wchar_t* name);
    ModuleID CoreLibrary();
private:
    struct Module
    {
        Microsoft::WRL::ComPtr<IMetaDataImport> metadata;
        std::wstring identity, name;
        AssemblyID assembly = 0;
        ModuleID manifest = 0;
        bool coreLibrary = false;
    };
    using Definition = std::pair<ModuleID, mdTypeDef>;
    ModuleID Assembly(ModuleID source, mdAssemblyRef reference);
    Definition Named(ModuleID module, const wchar_t* name, mdTypeDef enclosing, uint32_t depth);
    Definition Reference(ModuleID module, mdTypeRef token, uint32_t depth);
    std::mutex mutex_;
    std::map<std::tuple<ModuleID, mdTypeDef, std::vector<ClassID>>, ClassID> classes_;
    std::map<ModuleID, Module> modules_;
};

struct ManagedMethod
{
    FunctionID function = 0;
    ModuleID module = 0;
    mdMethodDef token = 0;
    uint32_t api = 0;
    void* owner = nullptr;
    std::wstring moduleName;
    std::wstring name;
    std::wstring parameters;
    std::string layout;
    std::vector<ManagedType> arguments;
    ManagedType result;
    bool decodedArguments = false;
    bool nativeDelegate = false;
    uint32_t instrumentedArguments = 0;
};

bool ReadManagedMethod(ICorProfilerInfo2* profiler, FunctionID function, ManagedMethod& method,
    ManagedClasses& classes, bool resolveGenerics = true);
bool ReadManagedMethod(ICorProfilerInfo2* profiler, ModuleID module, mdMethodDef token, ManagedMethod& method);
bool FrameworkModule(const std::wstring& path);
bool FrameworkIdentity(IMetaDataImport* metadata);
bool ReadManagedMethod(IMetaDataImport* metadata, const std::wstring& path, mdMethodDef token, ManagedMethod& method,
    std::vector<BYTE>* resultSignature = nullptr);

// Rewritten IL pins references only while the native callback copies these regions.
struct ManagedArgument
{
    const void* address;
    uint64_t bytes;
    const void* indirect;
    uint64_t indirectBytes;
    const void* buffer;
    uint64_t bufferBytes;
    uint64_t elementBytes;
};

enum class ManagedCallPhase : uint32_t { Enter, Leave, Tailcall };

using ManagedCallback = void (WINAPI*)(ManagedMethod*, const ManagedArgument*, ManagedCallPhase);
using ManagedSnapshotGuard = BOOL (WINAPI*)(BOOL);

HRESULT InstrumentManagedMethod(ICorProfilerInfo* profiler, ModuleID coreLibrary, ManagedMethod* method,
    std::span<const BYTE> original, ULONG stringLengthOffset, ULONG stringDataOffset,
    ManagedCallback callback, ManagedSnapshotGuard guard, std::vector<BYTE>& output);
}
