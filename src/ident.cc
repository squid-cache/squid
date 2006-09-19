
/*
 * $Id: ident.cc,v 1.74 2006/09/19 07:56:57 adrian Exp $
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
#include "comm.h"
#include "MemBuf.h"

#define IDENT_PORT 113
#define IDENT_KEY_SZ 50

typedef struct _IdentClient
{
    IDCB *callback;
    void *callback_data;

    struct _IdentClient *next;
}

IdentClient;

typedef struct _IdentStateData
{
    hash_link hash;		/* must be first */
    int fd;			/* IDENT fd */

    struct sockaddr_in me;

    struct sockaddr_in my_peer;
    IdentClient *clients;
    char buf[4096];
}

IdentStateData;

static IOCB identReadReply;
static PF identClose;
static PF identTimeout;
static CNCB identConnectDone;
static hash_table *ident_hash = NULL;
static void identClientAdd(IdentStateData *, IDCB *, void *);

/**** PRIVATE FUNCTIONS ****/

static void
identCallback(IdentStateData * state, char *result)
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

static void
identClose(int fdnotused, void *data)
{
    IdentStateData *state = (IdentStateData *)data;
    identCallback(state, NULL);
    comm_close(state->fd);
    hash_remove_link(ident_hash, (hash_link *) state);
    xfree(state->hash.key);
    cbdataFree(state);
}

static void
identTimeout(int fd, void *data)
{
    IdentStateData *state = (IdentStateData *)data;
    debug(30, 3) ("identTimeout: FD %d, %s\n", fd,
                  inet_ntoa(state->my_peer.sin_addr));
    comm_close(fd);
}

static void
identConnectDone(int fd, comm_err_t status, int xerrno, void *data)
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
              ntohs(state->my_peer.sin_port),
              ntohs(state->me.sin_port));
    comm_write_mbuf(fd, &mb, NULL, state);
    comm_read(fd, state->buf, BUFSIZ, identReadReply, state);
    commSetTimeout(fd, Config.Timeout.ident, identTimeout, state);
}

static void
identReadReply(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
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

    debug(30, 5) ("identReadReply: FD %d: Read '%s'\n", fd, buf);

    if (strstr(buf, "USERID")) {
        if ((ident = strrchr(buf, ':'))) {
            while (xisspace(*++ident))

                ;
            identCallback(state, ident);
        }
    }

    comm_close(fd);
}


static void
identClientAdd(IdentStateData * state, IDCB * callback, void *callback_data)
{
    IdentClient *c = (IdentClient *)xcalloc(1, sizeof(*c));
    IdentClient **C;
    c->callback = callback;
    c->callback_data = cbdataReference(callback_data);

    for (C = &state->clients; *C; C = &(*C)->next)

        ;
    *C = c;
}

CBDATA_TYPE(IdentStateData);

/**** PUBLIC FUNCTIONS ****/

/*
 * start a TCP connection to the peer host on port 113
 */
void

identStart(struct sockaddr_in *me, struct sockaddr_in *my_peer, IDCB * callback, void *data)
{
    IdentStateData *state;
    int fd;
    char key1[IDENT_KEY_SZ];
    char key2[IDENT_KEY_SZ];
    char key[IDENT_KEY_SZ];
    snprintf(key1, IDENT_KEY_SZ, "%s:%d",
             inet_ntoa(me->sin_addr),
             ntohs(me->sin_port));
    snprintf(key2, IDENT_KEY_SZ, "%s:%d",
             inet_ntoa(my_peer->sin_addr),
             ntohs(my_peer->sin_port));
    snprintf(key, IDENT_KEY_SZ, "%s,%s", key1, key2);

    if ((state = (IdentStateData *)hash_lookup(ident_hash, key)) != NULL)
    {
        identClientAdd(state, callback, data);
        return;
    }

    fd = comm_open(SOCK_STREAM,
                   IPPROTO_TCP,
                   me->sin_addr,
                   0,
                   COMM_NONBLOCKING,
                   "ident");

    if (fd == COMM_ERROR)
    {
        /* Failed to get a local socket */
        callback(NULL, data);
        return;
    }

    CBDATA_INIT_TYPE(IdentStateData);
    state = cbdataAlloc(IdentStateData);
    state->hash.key = xstrdup(key);
    state->fd = fd;
    state->me = *me;
    state->my_peer = *my_peer;
    identClientAdd(state, callback, data);
    hash_join(ident_hash, &state->hash);
    comm_add_close_handler(fd,
                           identClose,
                           state);
    commSetTimeout(fd, Config.Timeout.ident, identTimeout, state);
    commConnectStart(fd,
                     inet_ntoa(state->my_peer.sin_addr),
                     IDENT_PORT,
                     identConnectDone,
                     state);
}

void
identInit(void)
{
    ident_hash = hash_create((HASHCMP *) strcmp,
                             hashPrime(Squid_MaxFD / 8),
                             hash4);
}
