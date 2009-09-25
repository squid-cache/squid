/*
 * $Id$
 *
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
#include "ident/Config.h"
#include "ident/Ident.h"
#include "MemBuf.h"

namespace Ident
{

#define IDENT_PORT 113
#define IDENT_KEY_SZ 50

typedef struct _IdentClient {
    IDCB *callback;
    void *callback_data;

    struct _IdentClient *next;
} IdentClient;

typedef struct _IdentStateData {
    hash_link hash;		/* must be first */
    int fd;			/* IDENT fd */

    IpAddress me;

    IpAddress my_peer;
    IdentClient *clients;
    char buf[4096];
} IdentStateData;

// TODO: make these all a series of Async jobs. They are self-contained callbacks now.
static IOCB ReadReply;
static PF Close;
static PF Timeout;
static CNCB ConnectDone;
static hash_table *ident_hash = NULL;
static void ClientAdd(IdentStateData * state, IDCB * callback, void *callback_data);
static void identCallback(IdentStateData * state, char *result);

}; // namespace Ident

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
Ident::Close(int fdnotused, void *data)
{
    IdentStateData *state = (IdentStateData *)data;
    identCallback(state, NULL);
    comm_close(state->fd);
    hash_remove_link(ident_hash, (hash_link *) state);
    xfree(state->hash.key);
    cbdataFree(state);
}

void
Ident::Timeout(int fd, void *data)
{
    IdentStateData *state = (IdentStateData *)data;
    debugs(30, 3, "identTimeout: FD " << fd << ", " << state->my_peer);

    comm_close(fd);
}

void
Ident::ConnectDone(int fd, const DnsLookupDetails &, comm_err_t status, int xerrno, void *data)
{
    IdentStateData *state = (IdentStateData *)data;
    IdentClient *c;

    if (status != COMM_OK) {
        /* Failed to connect */
        comm_close(fd);
        return;
    }

    /*
     * see if any of our clients still care
     */
    for (c = state->clients; c; c = c->next) {
        if (cbdataReferenceValid(c->callback_data))
            break;
    }

    if (c == NULL) {
        /* no clients care */
        comm_close(fd);
        return;
    }

    MemBuf mb;
    mb.init();
    mb.Printf("%d, %d\r\n",
              state->my_peer.GetPort(),
              state->me.GetPort());
    comm_write_mbuf(fd, &mb, NULL, state);
    comm_read(fd, state->buf, BUFSIZ, Ident::ReadReply, state);
    commSetTimeout(fd, Ident::TheConfig.timeout, Ident::Timeout, state);
}

void
Ident::ReadReply(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    IdentStateData *state = (IdentStateData *)data;
    char *ident = NULL;
    char *t = NULL;

    assert (buf == state->buf);

    if (flag != COMM_OK || len <= 0) {
        comm_close(fd);
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

    debugs(30, 5, "identReadReply: FD " << fd << ": Read '" << buf << "'");

    if (strstr(buf, "USERID")) {
        if ((ident = strrchr(buf, ':'))) {
            while (xisspace(*++ident));
            Ident::identCallback(state, ident);
        }
    }

    comm_close(fd);
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
Ident::Start(IpAddress &me, IpAddress &my_peer, IDCB * callback, void *data)
{
    IdentStateData *state;
    int fd;
    char key1[IDENT_KEY_SZ];
    char key2[IDENT_KEY_SZ];
    char key[IDENT_KEY_SZ];
    char ntoabuf[MAX_IPSTRLEN];

    me.ToURL(key1, IDENT_KEY_SZ);
    my_peer.ToURL(key2, IDENT_KEY_SZ);
    snprintf(key, IDENT_KEY_SZ, "%s,%s", key1, key2);

    if (!ident_hash) {
        Init();
    }
    if ((state = (IdentStateData *)hash_lookup(ident_hash, key)) != NULL) {
        ClientAdd(state, callback, data);
        return;
    }

    IpAddress addr = me;
    addr.SetPort(0); // NP: use random port for secure outbound to IDENT_PORT

    fd = comm_open_listener(SOCK_STREAM,
                            IPPROTO_TCP,
                            addr,
                            COMM_NONBLOCKING,
                            "ident");

    if (fd == COMM_ERROR) {
        /* Failed to get a local socket */
        callback(NULL, data);
        return;
    }

    CBDATA_INIT_TYPE(IdentStateData);
    state = cbdataAlloc(IdentStateData);
    state->hash.key = xstrdup(key);
    state->fd = fd;
    state->me = me;
    state->my_peer = my_peer;
    ClientAdd(state, callback, data);
    hash_join(ident_hash, &state->hash);
    comm_add_close_handler(fd, Ident::Close, state);
    commSetTimeout(fd, Ident::TheConfig.timeout, Ident::Timeout, state);
    state->my_peer.NtoA(ntoabuf,MAX_IPSTRLEN);
    commConnectStart(fd, ntoabuf, IDENT_PORT, Ident::ConnectDone, state);
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
