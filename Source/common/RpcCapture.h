#pragma once
#include "CaptureValues.h"

namespace Detourist
{
RpcDecoder RpcDecoderFor(const char* module, const char* name);
uint32_t RpcPrefix(RpcDecoder decoder);
constexpr bool RpcDirectArguments(RpcDecoder decoder)
{
    return decoder == RpcDecoder::Client4 || decoder == RpcDecoder::Async4 || decoder == RpcDecoder::Pickle4;
}
constexpr bool RpcForwardedInterpreter(RpcDecoder outer, RpcDecoder inner)
{
    return outer == RpcDecoder::Client4 && inner == RpcDecoder::Client2 ||
        outer == RpcDecoder::Async4 && inner == RpcDecoder::Async2 ||
        outer == RpcDecoder::Pickle4 && inner == RpcDecoder::Pickle2;
}
void PrepareRpcCapture(RpcCaptureState& state, RpcDecoder decoder, const uint64_t* arguments);
struct ExportSignature;
bool PrepareRpcProxyCapture(RpcCaptureState& state, uint64_t table, const GUID* iid, uint32_t slot,
    ExportSignature* signature = nullptr);
void ReadRpcStackArguments(RpcCaptureState& state, uint64_t* arguments, uint64_t address);
bool WriteRpcStackArgument(const RpcCaptureState& state, uint32_t argument, uint64_t value);
void ObserveRpcDescriptorEdits(RpcCaptureState& state, const uint64_t* before, Event& event);
struct AsyncIoSink;
void FinishRpcAsync(const AsyncIoSink& sink, Event& event, AsyncIoRole role);
void CaptureRpcValues(RpcCaptureState& state, Event& event, Slot* slot, SharedHeader* header, bool leaving);
const char* RpcTypeName(RpcValueType type);
void DiscoverRpcMarshalers(const RpcCaptureState& state);
void CaptureRpcMarshalValues(const Event& event, Slot* slot, SharedHeader* header,
    uint32_t operation, uint32_t nativeBytes, bool leaving);
extern void (WINAPI* RpcMarshalObserver)(uint64_t, uint32_t, uint32_t);
constexpr bool RpcSerializationApi(Api api)
{
    return api == Api::MesEncodeIncrementalHandleCreate || api == Api::MesEncodeFixedBufferHandleCreate ||
        api == Api::MesEncodeDynBufferHandleCreate || api == Api::MesDecodeIncrementalHandleCreate ||
        api == Api::MesDecodeBufferHandleCreate || api == Api::MesIncrementalHandleReset ||
        api == Api::MesBufferHandleReset || api == Api::MesHandleFree;
}
void BeginRpcSerialization(Api api, const uint64_t* arguments);
void ObserveRpcSerialization(Api api, const uint64_t* arguments, uint64_t result);
void InvalidateRpcSerialization();
uint32_t RpcSerializationOperation(uint64_t handle);
extern uint32_t (WINAPI* RpcSerializationLookup)(uint64_t);
}
