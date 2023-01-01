/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 30    Ident (RFC 931) */

#include "squid.h"

#if USE_IDENT
#include "base/JobWait.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "CommCalls.h"
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

class IdentStateData
{
public:
    hash_link hash;     /* must be first */
private:
    CBDATA_CLASS(IdentStateData);

public:
    /* AsyncJob API emulated */
    void deleteThis(const char *aReason);
    void swanSong();

    /// notify all waiting IdentClient callbacks
    void notify(const char *result);

    Comm::ConnectionPointer conn;
    MemBuf queryMsg;  ///< the lookup message sent to IDENT server
    IdentClient *clients = nullptr;
    char buf[IDENT_BUFSIZE];

    /// waits for a connection to the IDENT server to be established/opened
    JobWait<Comm::ConnOpener> connWait;

private:
    // use deleteThis() to destroy
    ~IdentStateData();
};

CBDATA_CLASS_INIT(IdentStateData);

// TODO: make these all a series of Async job calls. They are self-contained callbacks now.
static IOCB ReadReply;
static IOCB WriteFeedback;
static CLCB Close;
static CTCB Timeout;
static CNCB ConnectDone;
static hash_table *ident_hash = nullptr;
static void ClientAdd(IdentStateData * state, IDCB * callback, void *callback_data);

} // namespace Ident

Ident::IdentConfig Ident::TheConfig;

void
Ident::IdentStateData::deleteThis(const char *reason)
{
    debugs(30, 3, reason);
    swanSong();
    delete this;
}

void
Ident::IdentStateData::swanSong()
{
    if (clients != nullptr)
        notify(nullptr);
}

Ident::IdentStateData::~IdentStateData() {
    assert(!clients);

    if (Comm::IsConnOpen(conn)) {
        comm_remove_close_handler(conn->fd, Ident::Close, this);
        conn->close();
    }

    hash_remove_link(ident_hash, (hash_link *) this);
    xfree(hash.key);
}

void
Ident::IdentStateData::notify(const char *result)
{
    while (IdentClient *client = clients) {
        void *cbdata;
        clients = client->next;

        if (cbdataReferenceValidDone(client->callback_data, &cbdata))
            client->callback(result, cbdata);

        xfree(client);
    }
}

void
Ident::Close(const CommCloseCbParams &params)
{
    IdentStateData *state = (IdentStateData *)params.data;
    if (state->conn) {
        state->conn->noteClosure();
        state->conn = nullptr;
    }
    state->deleteThis("connection closed");
}

void
Ident::Timeout(const CommTimeoutCbParams &io)
{
    debugs(30, 3, io.conn);
    IdentStateData *state = (IdentStateData *)io.data;
    state->deleteThis("timeout");
}

void
Ident::ConnectDone(const Comm::ConnectionPointer &conn, Comm::Flag status, int, void *data)
{
    IdentStateData *state = (IdentStateData *)data;
    state->connWait.finish();

    // Start owning the supplied connection (so that it is not orphaned if this
    // function bails early). As a (tiny) optimization or perhaps just diff
    // minimization, the close handler is added later, when we know we are not
    // bailing. This delay is safe because comm_remove_close_handler() forgives
    // missing handlers.
    assert(conn); // but may be closed
    assert(!state->conn);
    state->conn = conn;

    if (status != Comm::OK) {
        if (status == Comm::TIMEOUT)
            debugs(30, 3, "IDENT connection timeout to " << state->conn->remote);
        state->deleteThis(status == Comm::TIMEOUT ? "connect timeout" : "connect error");
        return;
    }

    /*
     * see if any of our clients still care
     */
    IdentClient *c;
    for (c = state->clients; c; c = c->next) {
        if (cbdataReferenceValid(c->callback_data))
            break;
    }

    if (c == nullptr) {
        state->deleteThis("client(s) aborted");
        return;
    }

    assert(state->conn->isOpen());
    comm_add_close_handler(state->conn->fd, Ident::Close, state);

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
Ident::WriteFeedback(const Comm::ConnectionPointer &conn, char *, size_t len, Comm::Flag flag, int xerrno, void *data)
{
    debugs(30, 5, conn << ": Wrote IDENT request " << len << " bytes.");

    // TODO handle write errors better. retry or abort?
    if (flag != Comm::OK) {
        debugs(30, 2, conn << " err-flags=" << flag << " IDENT write error: " << xstrerr(xerrno));
        IdentStateData *state = (IdentStateData *)data;
        state->deleteThis("write error");
    }
}

void
Ident::ReadReply(const Comm::ConnectionPointer &conn, char *buf, size_t len, Comm::Flag flag, int, void *data)
{
    IdentStateData *state = (IdentStateData *)data;
    char *ident = nullptr;
    char *t = nullptr;

    assert(buf == state->buf);
    assert(conn->fd == state->conn->fd);

    if (flag != Comm::OK || len <= 0) {
        state->deleteThis("read error");
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

    debugs(30, 5, conn << ": Read '" << buf << "'");

    if (strstr(buf, "USERID")) {
        if ((ident = strrchr(buf, ':'))) {
            while (xisspace(*++ident));
            if (ident && *ident == '\0')
                ident = nullptr;
            state->notify(ident);
        }
    }

    state->deleteThis("completed");
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

/*
 * start a TCP connection to the peer host on port 113
 */
void
Ident::Start(const Comm::ConnectionPointer &conn, IDCB * callback, void *data)
{
    IdentStateData *state;
    char key1[IDENT_KEY_SZ];
    char key2[IDENT_KEY_SZ];
    char key[IDENT_KEY_SZ*2+2]; // key1 + ',' + key2 + terminator

    conn->local.toUrl(key1, IDENT_KEY_SZ);
    conn->remote.toUrl(key2, IDENT_KEY_SZ);
    int res = snprintf(key, sizeof(key), "%s,%s", key1, key2);
    assert(res > 0);
    assert(static_cast<unsigned int>(res) < sizeof(key));

    if (!ident_hash) {
        ident_hash = hash_create((HASHCMP *) strcmp,
                                 hashPrime(Squid_MaxFD / 8),
                                 hash4);
    }
    if ((state = (IdentStateData *)hash_lookup(ident_hash, key)) != nullptr) {
        ClientAdd(state, callback, data);
        return;
    }

    state = new IdentStateData;
    state->hash.key = xstrdup(key);

    // copy the conn details. We do not want the original FD to be re-used by IDENT.
    const auto identConn = conn->cloneProfile();
    // NP: use random port for secure outbound to IDENT_PORT
    identConn->local.port(0);
    identConn->remote.port(IDENT_PORT);

    // build our query from the original connection details
    state->queryMsg.init();
    state->queryMsg.appendf("%d, %d\r\n", conn->remote.port(), conn->local.port());

    ClientAdd(state, callback, data);
    hash_join(ident_hash, &state->hash);

    AsyncCall::Pointer call = commCbCall(30,3, "Ident::ConnectDone", CommConnectCbPtrFun(Ident::ConnectDone, state));
    const auto connOpener = new Comm::ConnOpener(identConn, call, Ident::TheConfig.timeout);
    state->connWait.start(connOpener, call);
}

#endif /* USE_IDENT */

