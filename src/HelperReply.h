#ifndef _SQUID_SRC_HELPERREPLY_H
#define _SQUID_SRC_HELPERREPLY_H

#include "base/CbcPointer.h"
#include "MemBuf.h"
#include "Notes.h"

#if HAVE_OSTREAM
#include <ostream>
#endif

class helper_stateful_server;

/**
 * This object stores the reply message from a helper lookup
 * It provides parser routing to accept a raw buffer and process the
 * helper reply into fields for easy access by callers
 */
class HelperReply
{
private:
    // copy are prohibited for now
    HelperReply(const HelperReply &r);
    HelperReply &operator =(const HelperReply &r);

public:
    HelperReply() : result(HelperReply::Unknown), notes(), whichServer(NULL) {
        other_.init(1,1);
        other_.terminate();
    }

    // create/parse details from the msg buffer provided
    // XXX: buf should be const but parse() needs non-const for now
    HelperReply(char *buf, size_t len);

    const MemBuf &other() const { return other_; }

    /// backward compatibility:
    /// access to modifiable blob, required by redirectHandleReply()
    /// and by urlParse() in ClientRequestContext::clientRedirectDone()
    /// and by token blob/arg parsing in Negotiate auth handler
    MemBuf &modifiableOther() const { return *const_cast<MemBuf*>(&other_); }

    /** parse a helper response line format:
     *   line     := [ result ] *#( kv-pair )
     *   kv-pair := OWS token '=' ( quoted-string | token )
     *
     * token are URL-decoded.
     * quoted-string are \-escape decoded and the quotes are stripped.
     */
    // XXX: buf should be const but we may need strwordtok() and rfc1738_unescape()
    void parse(char *buf, size_t len);

public:
    /// The helper response 'result' field.
    enum Result_ {
        Unknown,      // no result code received, or unknown result code
        Okay,         // "OK" indicating success/positive result
        Error,        // "ERR" indicating success/negative result
        BrokenHelper, // "BH" indicating failure due to helper internal problems.

        // result codes for backward compatibility with NTLM/Negotiate
        // TODO: migrate to a variant of the above results with kv-pair parameters
        TT
    } result;

    // list of key=value pairs the helper produced
    NotePairs notes;

    /// for stateful replies the responding helper 'server' needs to be preserved across callbacks
    CbcPointer<helper_stateful_server> whichServer;

private:
    void parseResponseKeys();

    /// the remainder of the line
    MemBuf other_;
};

std::ostream &operator <<(std::ostream &os, const HelperReply &r);

#endif /* _SQUID_SRC_HELPERREPLY_H */
