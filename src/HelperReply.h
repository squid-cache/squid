#ifndef _SQUID_SRC_HELPERREPLY_H
#define _SQUID_SRC_HELPERREPLY_H

#include "base/CbcPointer.h"
#include "MemBuf.h"

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
    // implicit creation and copy are prohibited explicitly
    HelperReply();
    HelperReply(const HelperReply &r);
    HelperReply &operator =(const HelperReply &r);

public:
    // create/parse details from the msg buffer provided
    HelperReply(const char *buf, size_t len);
    ~HelperReply() {}

    const MemBuf &other() const { return other_; }

    /// backward compatibility:
    /// access to modifiable blob, required by redirectHandleReply()
    /// and by urlParse() in ClientRequestContext::clientRedirectDone()
    /// and by token blob/arg parsing in Negotiate auth handler
    MemBuf &modifiableOther() const { return *const_cast<MemBuf*>(&other_); }

public:
    /// The helper response 'result' field.
    enum Result_ {
        Unknown,      // no result code received, or unknown result code
        Okay,         // "OK" indicating success/positive result
        Error,        // "ERR" indicating failure/negative result
        BrokenHelper, // "BH" indicating failure due to helper internal problems.

        // some result codes for backward compatibility with NTLM/Negotiate
        // TODO: migrate these into variants of the above results with key-pair parameters
        TT,
        AF,
        NA
    } result;

// TODO other key=pair values. when the callbacks actually use this object.
// for now they retain their own parsing routines handling other()

    /// for stateful replies the responding helper 'server' needs to be preserved across callbacks
    CbcPointer<helper_stateful_server> whichServer;

private:
    /// the remainder of the line
    MemBuf other_;
};

std::ostream &operator <<(std::ostream &os, const HelperReply &r);

#endif /* _SQUID_SRC_HELPERREPLY_H */
