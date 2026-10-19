#pragma once
#include "Protocol.h"
#include <authz.h>

namespace Detourist
{
inline uint32_t AuditArgumentCount(uint32_t flags)
{
    // Some audit flags consume an extra index or obtain the logon ID directly from a token.
    switch (flags & AP_ParamTypeMask)
    {
    case APT_String: case APT_Pointer: case APT_Sid: case APT_Luid: case APT_Guid:
    case APT_Time: case APT_Int64: case APT_IpAddress: return 2;
    case APT_Ulong: return flags & AP_AccessMask ? 3 : 2;
    case APT_ObjectTypeList: return 3;
    case APT_LogonId: case APT_LogonIdWithSid:
        return flags & (AP_PrimaryLogonId | AP_ClientLogonId) ? 1 : 2;
    default: return 0;
    }
}

template<class Read> uint64_t ReadAuditArguments(Event& event, uint64_t maximum, Read read)
{
    uint64_t next = 5;
    auto argument = [&](uint32_t bytes, uint64_t& value)
    {
        value = 0;
        if (next >= maximum || !read(next, bytes, value)) return false;
        if (next < MaximumArguments) event.arguments[next] = value;
        ++next;
        return true;
    };

    // Decode only supplied slots; opaque pointer values never cause a memory probe.
    for (uint32_t index = 0, count = static_cast<uint32_t>(event.arguments[4]); index < count; ++index)
    {
        uint64_t value;
        if (!argument(4, value)) break;
        auto flags = static_cast<uint32_t>(value);
        auto slots = AuditArgumentCount(flags);
        if (!slots) break;
        if (slots > 1 && !argument((flags & AP_ParamTypeMask) == APT_Ulong ? 4 : sizeof(void*), value)) break;
        if (slots > 2 && !argument(4, value)) break;
    }
    auto captured = static_cast<uint32_t>(next < MaximumArguments ? next : MaximumArguments);
    event.flags = (event.flags & ~FormattedArgumentMask) | RawArguments | FormattedArguments |
        (captured << FormattedArgumentShift);
    return next;
}
}
