#define USE_STUBLESS_PROXY
#include <rpcproxy.h>

extern const ExtendedProxyFileInfo RpcObjectFixture_ProxyFileInfo;

const MIDL_STUBLESS_PROXY_INFO* RpcObjectMetadata(void)
{
    return (*RpcObjectFixture_ProxyFileInfo.pProxyVtblList)[0].header.pStublessProxyInfo;
}
