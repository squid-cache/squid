
/*
 * $Id: pconn.cc,v 1.53.4.1 2008/02/24 12:06:41 amosjeffries Exp $
 *
 * DEBUG: section 48    Persistent Connections
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
#include "CacheManager.h"
#include "Store.h"
#include "comm.h"
#include "pconn.h"
#include "fde.h"

#define PCONN_FDS_SZ	8	/* pconn set size, increase for better memcache hit rate */

static MemAllocator *pconn_fds_pool = NULL;
PconnModule * PconnModule::instance = NULL;
CBDATA_CLASS_INIT(IdleConnList);

/* ========== IdleConnList ============================================ */

IdleConnList::IdleConnList(const char *key, PconnPool *thePool) : parent(thePool)
{
    hash.key = xstrdup(key);
    nfds_alloc = PCONN_FDS_SZ;
    nfds = 0;
    fds = (int *)pconn_fds_pool->alloc();
}

IdleConnList::~IdleConnList()
{

    parent->unlinkList(this);

    if (nfds_alloc == PCONN_FDS_SZ)
        pconn_fds_pool->free(fds);
    else
        xfree(fds);

    xfree(hash.key);
}

int
IdleConnList::findFDIndex (int fd)
{
    int index;

    for (index = nfds - 1; index >= 0; --index) {
        if (fds[index] == fd)
            return index;
    }

    return -1;
}

void
IdleConnList::removeFD(int fd)
{
    int index = findFDIndex(fd);
    assert(index >= 0);
    debugs(48, 3, "IdleConnList::removeFD: found FD " << fd << " at index " << index);

    for (; index < nfds - 1; index++)
        fds[index] = fds[index + 1];

    if (--nfds == 0) {
        debugs(48, 3, "IdleConnList::removeFD: deleting " << hashKeyStr(&hash));
        delete this;
    }
}

void
IdleConnList::clearHandlers(int fd)
{
    comm_read_cancel(fd, IdleConnList::read, this);
    commSetTimeout(fd, -1, NULL, NULL);
}

void
IdleConnList::push(int fd)
{
    if (nfds == nfds_alloc) {
        debugs(48, 3, "IdleConnList::push: growing FD array");
        nfds_alloc <<= 1;
        int *old = fds;
        fds = (int *)xmalloc(nfds_alloc * sizeof(int));
        xmemcpy(fds, old, nfds * sizeof(int));

        if (nfds == PCONN_FDS_SZ)
            pconn_fds_pool->free(old);
        else
            xfree(old);
    }

    fds[nfds++] = fd;
    comm_read(fd, fakeReadBuf, sizeof(fakeReadBuf), IdleConnList::read, this);
    commSetTimeout(fd, Config.Timeout.pconn, IdleConnList::timeout, this);
}

/*
 * XXX this routine isn't terribly efficient - if there's a pending
 * read event (which signifies the fd will close in the next IO loop!)
 * we ignore the FD and move onto the next one. This means, as an example,
 * if we have a lot of FDs open to a very popular server and we get a bunch
 * of requests JUST as they timeout (say, it shuts down) we'll be wasting
 * quite a bit of CPU. Just keep it in mind.
 */
int
IdleConnList::findUseableFD()
{
    assert(nfds);

    for (int i=nfds-1; i>=0; i--) {
        if (!comm_has_pending_read_callback(fds[i])) {
            return fds[i];
        }
    }

    return -1;
}

void
IdleConnList::read(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    debugs(48, 3, "IdleConnList::read: " << len << " bytes from FD " << fd);

    if (flag == COMM_ERR_CLOSING) {
        /* Bail out early on COMM_ERR_CLOSING - close handlers will tidy up for us */
        return;
    }

    IdleConnList *list = (IdleConnList *) data;
    list->removeFD(fd);	/* might delete list */
    comm_close(fd);
}

void
IdleConnList::timeout(int fd, void *data)
{
    debugs(48, 3, "IdleConnList::timeout: FD " << fd);
    IdleConnList *list = (IdleConnList *) data;
    list->removeFD(fd);	/* might delete list */
    comm_close(fd);
}

/* ========== PconnPool PRIVATE FUNCTIONS ============================================ */

const char *

PconnPool::key(const char *host, u_short port, const char *domain, struct IN_ADDR *client_address)
{
    LOCAL_ARRAY(char, buf, SQUIDHOSTNAMELEN * 2 + 10);

    if (domain && client_address)
        snprintf(buf, SQUIDHOSTNAMELEN * 2 + 10, "%s:%d-%s/%s", host, (int) port, inet_ntoa(*client_address), domain);
    else if (domain && (!client_address))
        snprintf(buf, SQUIDHOSTNAMELEN * 2 + 10, "%s:%d/%s", host, (int) port, domain);
    else if ((!domain) && client_address)
        snprintf(buf, SQUIDHOSTNAMELEN * 2 + 10, "%s:%d-%s", host, (int) port, inet_ntoa(*client_address));
    else
        snprintf(buf, SQUIDHOSTNAMELEN * 2 + 10, "%s:%d", host, (int) port);

    return buf;
}

void
PconnPool::dumpHist(StoreEntry * e)
{
    int i;
    storeAppendPrintf(e,
                      "%s persistent connection counts:\n"
                      "\n"
                      "\treq/\n"
                      "\tconn      count\n"
                      "\t----  ---------\n",
                      descr);

    for (i = 0; i < PCONN_HIST_SZ; i++) {
        if (hist[i] == 0)
            continue;

        storeAppendPrintf(e, "\t%4d  %9d\n", i, hist[i]);
    }
}

/* ========== PconnPool PUBLIC FUNCTIONS ============================================ */

PconnPool::PconnPool(const char *aDescr) : table(NULL), descr(aDescr)
{
    int i;
    table = hash_create((HASHCMP *) strcmp, 229, hash_string);

    for (i = 0; i < PCONN_HIST_SZ; i++)
        hist[i] = 0;

    PconnModule::GetInstance()->add
    (this);
}

void

PconnPool::push(int fd, const char *host, u_short port, const char *domain, struct IN_ADDR *client_address)
{

    IdleConnList *list;
    const char *aKey;
    LOCAL_ARRAY(char, desc, FD_DESC_SZ);

    if (fdUsageHigh())
    {
        debugs(48, 3, "PconnPool::push: Not many unused FDs");
        comm_close(fd);
        return;
    } else if (shutting_down)
    {
        comm_close(fd);
        return;
    }

    aKey = key(host, port, domain, client_address);

    list = (IdleConnList *) hash_lookup(table, aKey);

    if (list == NULL)
    {
        list = new IdleConnList(aKey, this);
        debugs(48, 3, "pconnNew: adding " << hashKeyStr(&list->hash));
        hash_join(table, &list->hash);
    }

    list->push(fd);

    assert(!comm_has_incomplete_write(fd));
    snprintf(desc, FD_DESC_SZ, "%s idle connection", host);
    fd_note(fd, desc);
    debugs(48, 3, "PconnPool::push: pushed FD " << fd << " for " << aKey);
}

/*
 * Return a pconn fd for host:port if available and retriable.
 * Otherwise, return -1.
 *
 * We close available persistent connection if the caller transaction is not
 * retriable to avoid having a growing number of open connections when many
 * transactions create persistent connections but are not retriable.
 */
int

PconnPool::pop(const char *host, u_short port, const char *domain, struct IN_ADDR *client_address, bool isRetriable)
{
    IdleConnList *list;
    const char * aKey = key(host, port, domain, client_address);
    list = (IdleConnList *)hash_lookup(table, aKey);

    if (list == NULL)
        return -1;

    int fd = list->findUseableFD(); // search from the end. skip pending reads.

    if (fd >= 0)
    {
        list->clearHandlers(fd);
        list->removeFD(fd);	/* might delete list */

        if (!isRetriable) {
            comm_close(fd);
            return -1;
        }
    }

    return fd;
}

void
PconnPool::unlinkList(IdleConnList *list) const
{
    hash_remove_link(table, &list->hash);
}

void
PconnPool::count(int uses)
{
    if (uses >= PCONN_HIST_SZ)
        uses = PCONN_HIST_SZ - 1;

    hist[uses]++;
}

/* ========== PconnModule ============================================ */

/*
 * This simple class exists only for the cache manager
 */

PconnModule::PconnModule() : pools(NULL), poolCount(0)
{
    pools = (PconnPool **) xcalloc(MAX_NUM_PCONN_POOLS, sizeof(*pools));
    pconn_fds_pool = memPoolCreate("pconn_fds", PCONN_FDS_SZ * sizeof(int));
    debugs(48, 0, "persistent connection module initialized");
}

PconnModule *
PconnModule::GetInstance()
{
    if (instance == NULL)
        instance = new PconnModule;

    return instance;
}

void
PconnModule::registerWithCacheManager(CacheManager & manager)
{
    manager.registerAction("pconn",
                           "Persistent Connection Utilization Histograms",
                           DumpWrapper, 0, 1);
}

void

PconnModule::add
    (PconnPool *aPool)
{
    assert(poolCount < MAX_NUM_PCONN_POOLS);
    *(pools+poolCount) = aPool;
    poolCount++;
}

void
PconnModule::dump(StoreEntry *e)
{
    int i;

    for (i = 0; i < poolCount; i++) {
        (*(pools+i))->dumpHist(e);
    }
}

void
PconnModule::DumpWrapper(StoreEntry *e)
{
    PconnModule::GetInstance()->dump(e);
}
