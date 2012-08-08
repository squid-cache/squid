#ifndef _SQUID_SRC_ANYP_PROTOCOLTYPE_H
#define _SQUID_SRC_ANYP_PROTOCOLTYPE_H

#if HAVE_OSTREAM
#include <ostream>
#endif

namespace AnyP
{

/**
 * List of all protocols known and supported.
 * This is a combined list. It is used as type-codes where needed and
 * the AnyP::ProtocolType_Str array of strings may be used for display
 */
typedef enum {
    PROTO_NONE = 0,
    PROTO_HTTP,
    PROTO_FTP,
    PROTO_HTTPS,
    PROTO_COAP,
    PROTO_COAPS,
    PROTO_GOPHER,
    PROTO_WAIS,
    PROTO_CACHE_OBJECT,
    PROTO_ICP,
#if USE_HTCP
    PROTO_HTCP,
#endif
    PROTO_URN,
    PROTO_WHOIS,
    PROTO_INTERNAL,
    PROTO_ICY,
    PROTO_UNKNOWN,
    PROTO_MAX
} ProtocolType;

extern const char *ProtocolType_str[];

/** Display the registered Protocol Type (in upper case).
 *  If the protocol is not a registered AnyP::ProtocolType nothing will be displayed.
 * The caller is responsible for any alternative text.
 */
inline std::ostream &
operator <<(std::ostream &os, ProtocolType const &p)
{
    if (PROTO_NONE <= p && p < PROTO_MAX)
        os << ProtocolType_str[p];
    else
        os << static_cast<int>(p);
    return os;
}

} // namespace AnyP

#endif /* _SQUID_SRC_ANYP_PROTOCOLTYPE_H */
