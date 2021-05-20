/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ClientActiveRequests.h"
#include "client_side_request.h"
#include "fde.h"
#include "http/Stream.h"
#include "ip/forward.h"
#include "mgr/Registration.h"
#include "Store.h"
#include "util.h"

dlink_list ClientActiveRequests;

static void
statClientRequests(StoreEntry *s)
{
    dlink_node *i;
    ClientHttpRequest *http;
    StoreEntry *e;
    char buf[MAX_IPSTRLEN];

    for (i = ClientActiveRequests.head; i; i = i->next) {
        const char *p = NULL;
        http = static_cast<ClientHttpRequest *>(i->data);
        assert(http);
        ConnStateData *conn = http->getConn();
        storeAppendPrintf(s, "Connection: %p\n", conn);

        if (conn != NULL) {
            const int fd = conn->clientConnection->fd;
            storeAppendPrintf(s, "\tFD %d, read %" PRId64 ", wrote %" PRId64 "\n", fd,
                              fd_table[fd].bytes_read, fd_table[fd].bytes_written);
            storeAppendPrintf(s, "\tFD desc: %s\n", fd_table[fd].desc);
            storeAppendPrintf(s, "\tin: buf %p, used %ld, free %ld\n",
                              conn->inBuf.rawContent(), (long int)conn->inBuf.length(), (long int)conn->inBuf.spaceSize());
            storeAppendPrintf(s, "\tremote: %s\n",
                              conn->clientConnection->remote.toUrl(buf, MAX_IPSTRLEN));
            storeAppendPrintf(s, "\tlocal: %s\n",
                              conn->clientConnection->local.toUrl(buf, MAX_IPSTRLEN));
            storeAppendPrintf(s, "\tnrequests: %u\n", conn->pipeline.nrequests);
        }

        storeAppendPrintf(s, "uri %s\n", http->uri);
        storeAppendPrintf(s, "logType %s\n", http->logType.c_str());
        storeAppendPrintf(s, "out.offset %ld, out.size %lu\n",
                          (long int)http->out.offset, (unsigned long int)http->out.size);
        storeAppendPrintf(s, "req_sz %ld\n", (long int)http->req_sz);
        e = http->storeEntry();
        storeAppendPrintf(s, "entry %p/%s\n", e, e ? e->getMD5Text() : "N/A");
        storeAppendPrintf(s, "start %ld.%06d (%f seconds ago)\n",
                          (long int)http->al->cache.start_time.tv_sec,
                          (int)http->al->cache.start_time.tv_usec,
                          tvSubDsec(http->al->cache.start_time, current_time));
#if USE_AUTH
        if (http->request->auth_user_request != NULL)
            p = http->request->auth_user_request->username();
        else
#endif
            if (http->request->extacl_user.size() > 0) {
                p = http->request->extacl_user.termedBuf();
            }

        if (!p && conn != NULL && conn->clientConnection->rfc931[0])
            p = conn->clientConnection->rfc931;

#if USE_OPENSSL
        if (!p && conn != NULL && Comm::IsConnOpen(conn->clientConnection))
            p = sslGetUserEmail(fd_table[conn->clientConnection->fd].ssl.get());
#endif

        if (!p)
            p = dash_str;

        storeAppendPrintf(s, "username %s\n", p);

#if USE_DELAY_POOLS
        storeAppendPrintf(s, "delay_pool %d\n", DelayId::DelayClient(http).pool());
#endif

        storeAppendPrintf(s, "\n");
    }
}

void
ClientActiveRequestsInit()
{
    Mgr::RegisterAction("active_requests",
                        "Client-side Active Requests",
                        statClientRequests, 0, 1);
}

