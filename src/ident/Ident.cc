/*
 * DEBUG: section 30    Ident (RFC 931)
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#include "squid.h"

#if USE_IDENT
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "CommCalls.h"
#include "comm/Write.h"
#include "globals.h"
#include "ident/Config.h"
#include "ident/Ident.h"
#include "MemBuf.h"

namespace Ident
{

#define IDENT_PORT 113
#define IDENT_KEY_SZ 50
#define IDENT_BUFSIZE 4096

typedef struct _IdentClient {
    IDCB *callback;
    void *callback_data;

    struct _IdentClient *next;
} IdentClient;

typedef struct _IdentStateData {
    hash_link hash;		/* must be first */
    Comm::ConnectionPointer conn;
    MemBuf queryMsg;  ///< the lookup message sent to IDENT server
    IdentClient *clients;
    char buf[IDENT_BUFSIZE];
} IdentStateData;

// TODO: make these all a series of Async job calls. They are self-contained callbacks now.
static IOCB ReadReply;
static IOCB WriteFeedback;
static CLCB Close;
static CTCB Timeout;
static CNCB ConnectDone;
static hash_table *ident_hash = NULL;
static void ClientAdd(IdentStateData * state, IDCB * callback, void *callback_data);
static void identCallback(IdentStateData * state, char *result);

} // namespace Ident

Ident::IdentConfig Ident::TheConfig;

/**** PRIVATE FUNCTIONS ****/

void
Ident::identCallback(IdentStateData * state, char *result)
{
    IdentClient *client;

    if (result && *result == '\0')
        result = NULL;

    while ((client = state->clients)) {
        void *cbdata;
        state->clients = client->next;

        if (cbdataReferenceValidDone(client->callback_data, &cbdata))
            client->callback(result, cbdata);

        xfree(client);
    }
}

void
Ident::Close(const CommCloseCbParams &params)
{
    IdentStateData *state = (IdentStateData *)params.data;
    identCallback(state, NULL);
    state->conn->close();
    hash_remove_link(ident_hash, (hash_link *) state);
    xfree(state->hash.key);
    cbdataFree(state);
}

void
Ident::Timeout(const CommTimeoutCbParams &io)
{
    debugs(30, 3, HERE << io.conn);
    io.conn->close();
}

void
Ident::ConnectDone(const Comm::ConnectionPointer &conn, comm_err_t status, int xerrno, void *data)
{
    IdentStateData *state = (IdentStateData *)data;

    if (status != COMM_OK) {
        if (status == COMM_TIMEOUT) {
            debugs(30, 3, "IDENT connection timeout to " << state->conn->remote);
        }
        return;
    }

    assert(conn != NULL && conn == state->conn);

    /*
     * see if any of our clients still care
     */
    IdentClient *c;
    for (c = state->clients; c; c = c->next) {
        if (cbdataReferenceValid(c->callback_data))
            break;
    }

    if (c == NULL) {
        /* no clients care */
        conn->close();
        return;
    }

    comm_add_close_handler(conn->fd, Ident::Close, state);

    AsyncCall::Pointer writeCall = commCbCall(5,4, "Ident::WriteFeedback",
                                   CommIoCbPtrFun(Ident::WriteFeedback, state));
    Comm::Write(conn, &state->queryMsg, writeCall);
    AsyncCall::Pointer readCall = commCbCall(5,4, "Ident::ReadReply",
                                  CommIoCbPtrFun(Ident::ReadReply, state));
    comm_read(conn, state->buf, IDENT_BUFSIZE, readCall);
    AsyncCall::Pointer timeoutCall = commCbCall(5,4, "Ident::Timeout",
                                     CommTimeoutCbPtrFun(Ident::Timeout, state));
    commSetConnTimeout(conn, Ident::TheConfig.timeout, timeoutCall);
}

void
Ident::WriteFeedback(const Comm::ConnectionPointer &conn, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    debugs(30, 5, HERE << conn << ": Wrote IDENT request " << len << " bytes.");

    // TODO handle write errors better. retry or abort?
    if (flag != COMM_OK) {
        debugs(30, 2, HERE << conn << " err-flags=" << flag << " IDENT write error: " << xstrerr(xerrno));
        conn->close();
    }
}

void
Ident::ReadReply(const Comm::ConnectionPointer &conn, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    IdentStateData *state = (IdentStateData *)data;
    char *ident = NULL;
    char *t = NULL;

    assert(buf == state->buf);
    assert(conn->fd == state->conn->fd);

    if (flag != COMM_OK || len <= 0) {
        state->conn->close();
        return;
    }

    /*
     * XXX This isn't really very tolerant. It should read until EOL
     * or EOF and then decode the answer... If the reply is fragmented
     * then this will fail
     */
    buf[len] = '\0';

    if ((t = strchr(buf, '\r')))
        *t = '\0';

    if ((t = strchr(buf, '\n')))
        *t = '\0';

    debugs(30, 5, HERE << conn << ": Read '" << buf << "'");

    if (strstr(buf, "USERID")) {
        if ((ident = strrchr(buf, ':'))) {
            while (xisspace(*++ident));
            Ident::identCallback(state, ident);
        }
    }

    state->conn->close();
}

void
Ident::ClientAdd(IdentStateData * state, IDCB * callback, void *callback_data)
{
    IdentClient *c = (IdentClient *)xcalloc(1, sizeof(*c));
    IdentClient **C;
    c->callback = callback;
    c->callback_data = cbdataReference(callback_data);

    for (C = &state->clients; *C; C = &(*C)->next);
    *C = c;
}

CBDATA_TYPE(IdentStateData);

/**** PUBLIC FUNCTIONS ****/

/*
 * start a TCP connection to the peer host on port 113
 */
void
Ident::Start(const Comm::ConnectionPointer &conn, IDCB * callback, void *data)
{
    IdentStateData *state;
    char key1[IDENT_KEY_SZ];
    char key2[IDENT_KEY_SZ];
    char key[IDENT_KEY_SZ];

    conn->local.ToURL(key1, IDENT_KEY_SZ);
    conn->remote.ToURL(key2, IDENT_KEY_SZ);
    snprintf(key, IDENT_KEY_SZ, "%s,%s", key1, key2);

    if (!ident_hash) {
        Init();
    }
    if ((state = (IdentStateData *)hash_lookup(ident_hash, key)) != NULL) {
        ClientAdd(state, callback, data);
        return;
    }

    CBDATA_INIT_TYPE(IdentStateData);
    state = cbdataAlloc(IdentStateData);
    state->hash.key = xstrdup(key);

    // copy the conn details. We dont want the original FD to be re-used by IDENT.
    state->conn = conn->copyDetails();
    // NP: use random port for secure outbound to IDENT_PORT
    state->conn->local.SetPort(0);
    state->conn->remote.SetPort(IDENT_PORT);

    // build our query from the original connection details
    state->queryMsg.init();
    state->queryMsg.Printf("%d, %d\r\n", conn->remote.GetPort(), conn->local.GetPort());

    ClientAdd(state, callback, data);
    hash_join(ident_hash, &state->hash);

    AsyncCall::Pointer call = commCbCall(30,3, "Ident::ConnectDone", CommConnectCbPtrFun(Ident::ConnectDone, state));
    AsyncJob::Start(new Comm::ConnOpener(state->conn, call, Ident::TheConfig.timeout));
}

void
Ident::Init(void)
{
    if (ident_hash) {
        debugs(30, DBG_CRITICAL, "WARNING: Ident already initialized.");
        return;
    }

    ident_hash = hash_create((HASHCMP *) strcmp,
                             hashPrime(Squid_MaxFD / 8),
                             hash4);
}

#endif /* USE_IDENT */
