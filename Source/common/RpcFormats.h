#pragma once
#include "RpcCapture.h"

namespace Detourist
{
constexpr uint32_t RpcSlotBytes = sizeof(void*);
constexpr uint32_t RpcMaxPointerDepth = 16;
constexpr uint32_t RpcMaxProxyProcedures = 4096;
constexpr uint32_t RpcMaxVtableSlots = 512;
constexpr uint32_t IUnknownSlotCount = 3;
constexpr size_t RpcSerializationHandleCapacity = 4096;
constexpr uint32_t RpcMaxExpressionDepth = 32;
constexpr uint32_t RpcMaxExpressionBudget = 256;
constexpr uint32_t RpcMaxUnionArms = 4096;
constexpr uint32_t RpcMaxMembers = 128;
constexpr uint32_t RpcMaxPointers = 64;
enum class RpcSerializationMode : uint32_t { None, Encode, Decode, EncodeDynBuffer };
bool ReadRpcMemory(const void* source, void* destination, size_t bytes);
template<class Type> bool ReadRpc(uint64_t address, Type& value)
{
    return address && address <= UINTPTR_MAX - sizeof(Type) &&
        ReadRpcMemory(reinterpret_cast<const void*>(address), &value, sizeof(value));
}
RpcValueType RpcScalar(uint8_t code, bool ndr64, uint8_t& bytes);
bool RpcPointer(uint64_t& format, bool ndr64, uint8_t& code);
uint32_t RpcMemorySize(uint64_t format, bool ndr64, uint32_t correlationBytes = 4);
struct RpcArrayExtent
{
    uint64_t capacity = 0, bytes = 0, element = 0, pointers = 0;
    uint32_t stride = 0;
};
bool RpcArray(const RpcCaptureState& state, const Event& event, uint64_t format, bool leaving,
    RpcArrayExtent& result, bool capacityOnly = false, uint64_t memory = 0, uint64_t container = 0);
struct RpcUnionExtent
{
    uint64_t arm = 0, switchValue = 0;
    uint32_t bytes = 0, offset = 0;
    uint8_t armCode = 0, switchCode = 0;
};
bool RpcUnion(const RpcCaptureState& state, const Event& event, uint64_t format, bool leaving,
    uint64_t memory, uint64_t container, RpcUnionExtent& result);
}
