/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTP_CONTROL_MSG_H
#define SQUID_HTTP_CONTROL_MSG_H

#include "base/AsyncCall.h"
#include "HttpReply.h"

class CommIoCbParams;
class HttpControlMsg;

/*
 * This API exists to throttle forwarding of 1xx messages from the server
 * side (Source == HttpStateData) to the client side (Sink == ConnStateData).
 *
 * Without throttling, Squid would have to drop some 1xx responses to
 * avoid DoS attacks that send many 1xx responses without reading them.
 * Dropping 1xx responses without violating HTTP is as complex as throttling.
 */

/// sends a single control message, notifying the Sink
class HttpControlMsgSink: public virtual AsyncJob
{
public:
    HttpControlMsgSink(): AsyncJob("unused") {}

    /// called to send the 1xx message and notify the Source
    virtual void sendControlMsg(HttpControlMsg msg) = 0;

    virtual void doneWithControlMsg();

    /// callback to handle Comm::Write completion
    void wroteControlMsg(const CommIoCbParams &);

    /// Call to schedule when the control msg has been sent
    AsyncCall::Pointer cbControlMsgSent;
};

/// bundles HTTP 1xx reply and the "successfully forwarded" callback
class HttpControlMsg
{
public:
    typedef AsyncCall::Pointer Callback;

    HttpControlMsg(const HttpReply::Pointer &aReply, const Callback &aCallback):
        reply(aReply), cbSuccess(aCallback) {}

public:
    HttpReply::Pointer reply; ///< the 1xx message being forwarded
    Callback cbSuccess; ///< called after successfully writing the 1xx message

    // We could add an API to notify of send failures as well, but the
    // current Source and Sink are tied via Store anyway, so the Source
    // will know, eventually, if the Sink is gone or otherwise failed.
};

inline std::ostream &
operator <<(std::ostream &os, const HttpControlMsg &msg)
{
    return os << msg.reply << ", " << msg.cbSuccess;
}

#endif /* SQUID_HTTP_CONTROL_MSG_H */

