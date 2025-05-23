/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_QUEUENODE_H
#define SQUID_SRC_AUTH_QUEUENODE_H

#include "auth/UserRequest.h"
#include "cbdata.h"
#include "mem/AllocatorProxy.h"

namespace Auth
{

/**
 * A queue of auth requests waiting for verification to occur.
 *
 * Certain authentication schemes such a Basic and Bearer auth
 * permit credentials tokens to be repeated from multiple sources
 * simultaneously. This queue node allows multiple validation
 * queries to be collapsed into one backend helper lookup.
 * CBDATA and handlers stored in these queue nodes can be notified
 * all at once with a result when the lookup completes.
 */
class QueueNode
{
    MEMPROXY_CLASS(Auth::QueueNode);

private:
    // we store CBDATA here, copy is not safe
    QueueNode(const QueueNode &);
    QueueNode &operator =(const QueueNode &);

public:
    QueueNode(Auth::UserRequest *aRequest, AUTHCB *aHandler, void *aData) :
        next(nullptr),
        auth_user_request(aRequest),
        handler(aHandler),
        data(cbdataReference(aData)) {}
    ~QueueNode() {
        cbdataReferenceDone(data);
        while (next) {
            QueueNode *tmp = next->next;
            next->next = nullptr;
            delete next;
            next = tmp;
        };
    }

    Auth::QueueNode *next;
    Auth::UserRequest::Pointer auth_user_request;
    AUTHCB *handler;
    void *data;
};

} // namespace Auth

#endif /* SQUID_SRC_AUTH_QUEUENODE_H */

