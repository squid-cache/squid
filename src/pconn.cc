/*
 * $Id$
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
#include "comm.h"
#include "comm/Connection.h"
#include "fde.h"
#include "pconn.h"
#include "Store.h"

#define PCONN_FDS_SZ	8	/* pconn set size, increase for better memcache hit rate */

//TODO: re-attach to MemPools. WAS: static MemAllocator *pconn_fds_pool = NULL;
PconnModule * PconnModule::instance = NULL;
CBDATA_CLASS_INIT(IdleConnList);

/* ========== IdleConnList ============================================ */

IdleConnList::IdleConnList(const char *key, PconnPool *thePool) :
        nfds_alloc(PCONN_FDS_SZ),
        nfds(0),
        parent(thePool)
{
    hash.key = xstrdup(key);
    theList = new Comm::ConnectionPointer[nfds_alloc];
// TODO: re-attach to MemPools. WAS: fds = (int *)pconn_fds_pool->alloc();
}

IdleConnList::~IdleConnList()
{
    parent->unlinkList(this);

/* TODO: re-attach to MemPools.
    if (nfds_alloc == PCONN_FDS_SZ)
        pconn_fds_pool->freeOne(theList);
    else
*/
    delete[] theList;

    xfree(hash.key);
}

int
IdleConnList::findIndex(const Comm::ConnectionPointer &conn)
{
    for (int index = nfds - 1; index >= 0; --index) {
        if (theList[index]->fd == conn->fd)
            return index;
    }

    return -1;
}

bool
IdleConnList::remove(const Comm::ConnectionPointer &conn)
{
    int index = findIndex(conn);
    if (index < 0) {
        debugs(48, 2, HERE << conn << " NOT FOUND!");
        return false;
    }
    debugs(48, 3, HERE << "found " << conn << " at index " << index);

    for (; index < nfds - 1; index++)
        theList[index] = theList[index + 1];

    if (--nfds == 0) {
        debugs(48, 3, "IdleConnList::removeFD: deleting " << hashKeyStr(&hash));
        delete this;
    }
    return true;
}

void
IdleConnList::clearHandlers(const Comm::ConnectionPointer &conn)
{
    comm_read_cancel(conn->fd, IdleConnList::read, this);
    commSetTimeout(conn->fd, -1, NULL, NULL);
}

void
IdleConnList::push(const Comm::ConnectionPointer &conn)
{
    if (nfds == nfds_alloc) {
        debugs(48, 3, "IdleConnList::push: growing FD array");
        nfds_alloc <<= 1;
        const Comm::ConnectionPointer *oldList = theList;
        theList = new Comm::ConnectionPointer[nfds_alloc];
        for (int index = 0; index < nfds; index++)
            theList[index] = oldList[index];

/* TODO: re-attach to MemPools.
        if (nfds == PCONN_FDS_SZ)
            pconn_fds_pool->freeOne(oldList);
        else
*/
        delete[] oldList;
    }

    theList[nfds++] = conn;
    comm_read(conn, fakeReadBuf, sizeof(fakeReadBuf), IdleConnList::read, this);
    commSetTimeout(conn->fd, Config.Timeout.pconn, IdleConnList::timeout, this);
}

/*
 * XXX this routine isn't terribly efficient - if there's a pending
 * read event (which signifies the fd will close in the next IO loop!)
 * we ignore the FD and move onto the next one. This means, as an example,
 * if we have a lot of FDs open to a very popular server and we get a bunch
 * of requests JUST as they timeout (say, it shuts down) we'll be wasting
 * quite a bit of CPU. Just keep it in mind.
 */
Comm::ConnectionPointer
IdleConnList::findUseable()
{
    assert(nfds);

    for (int i=nfds-1; i>=0; i--) {
        if (!comm_has_pending_read_callback(theList[i]->fd)) {
            return theList[i];
        }
    }

    return Comm::ConnectionPointer();
}

void
IdleConnList::read(const Comm::ConnectionPointer &conn, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    debugs(48, 3, HERE << len << " bytes from " << conn);

    if (flag == COMM_ERR_CLOSING) {
        /* Bail out early on COMM_ERR_CLOSING - close handlers will tidy up for us */
        return;
    }

    IdleConnList *list = (IdleConnList *) data;
    /* might delete list */
    if (list && list->remove(conn)) {
        Comm::ConnectionPointer nonConst = conn;
        nonConst->close();
    }
}

void
IdleConnList::timeout(int fd, void *data)
{
    debugs(48, 3, "IdleConnList::timeout: FD " << fd);
    IdleConnList *list = (IdleConnList *) data;
    Comm::ConnectionPointer temp = new Comm::Connection; // XXX: transition. make timeouts pass conn in
    temp->fd = fd;
    if (list->remove(temp)) {
        temp->close();
    } else
        temp->fd = -1; // XXX: transition. prevent temp erasure double-closing FD until timeout CB passess conn in.
}

/* ========== PconnPool PRIVATE FUNCTIONS ============================================ */

const char *
PconnPool::key(const Comm::ConnectionPointer &destLink, const char *domain)
{
    LOCAL_ARRAY(char, buf, SQUIDHOSTNAMELEN * 3 + 10);

    destLink->remote.ToURL(buf, SQUIDHOSTNAMELEN * 3 + 10);
    if (domain) {
        int used = strlen(buf);
        snprintf(buf+used, SQUIDHOSTNAMELEN * 3 + 10-used, "/%s", domain);
    }

    debugs(48,6,"PconnPool::key(" << destLink << ", " << (domain?domain:"[no domain]") << ") is {" << buf << "}" );
    return buf;
}

void
PconnPool::dumpHist(StoreEntry * e) const
{
    storeAppendPrintf(e,
                      "%s persistent connection counts:\n"
                      "\n"
                      "\treq/\n"
                      "\tconn      count\n"
                      "\t----  ---------\n",
                      descr);

    for (int i = 0; i < PCONN_HIST_SZ; i++) {
        if (hist[i] == 0)
            continue;

        storeAppendPrintf(e, "\t%4d  %9d\n", i, hist[i]);
    }
}

void
PconnPool::dumpHash(StoreEntry *e) const
{
    hash_table *hid = table;
    hash_first(hid);

    int i = 0;
    for (hash_link *walker = hid->next; walker; walker = hash_next(hid)) {
        storeAppendPrintf(e, "\t item %5d: %s\n", i++, (char *)(walker->key));
    }
}

/* ========== PconnPool PUBLIC FUNCTIONS ============================================ */

PconnPool::PconnPool(const char *aDescr) : table(NULL), descr(aDescr)
{
    table = hash_create((HASHCMP *) strcmp, 229, hash_string);

    for (int i = 0; i < PCONN_HIST_SZ; i++)
        hist[i] = 0;

    PconnModule::GetInstance()->add(this);
}

PconnPool::~PconnPool()
{
    descr = NULL;
    hashFreeMemory(table);
}

void
PconnPool::push(const Comm::ConnectionPointer &conn, const char *domain)
{
    if (fdUsageHigh()) {
        debugs(48, 3, "PconnPool::push: Not many unused FDs");
        Comm::ConnectionPointer nonConst = conn;
        nonConst->close();
        return;
    } else if (shutting_down) {
        Comm::ConnectionPointer nonConst = conn;
        nonConst->close();
        debugs(48, 3, "PconnPool::push: Squid is shutting down. Refusing to do anything");
        return;
    }

    const char *aKey = key(conn, domain);
    IdleConnList *list = (IdleConnList *) hash_lookup(table, aKey);

    if (list == NULL) {
        list = new IdleConnList(aKey, this);
        debugs(48, 3, "PconnPool::push: new IdleConnList for {" << hashKeyStr(&list->hash) << "}" );
        hash_join(table, &list->hash);
    } else {
        debugs(48, 3, "PconnPool::push: found IdleConnList for {" << hashKeyStr(&list->hash) << "}" );
    }

    list->push(conn);
    assert(!comm_has_incomplete_write(conn->fd));

    LOCAL_ARRAY(char, desc, FD_DESC_SZ);
    snprintf(desc, FD_DESC_SZ, "Idle: %s", aKey);
    fd_note(conn->fd, desc);
    debugs(48, 3, HERE << "pushed " << conn << " for " << aKey);
}

bool
PconnPool::pop(Comm::ConnectionPointer &destLink, const char *domain, bool isRetriable)
{
    const char * aKey = key(destLink, domain);

    IdleConnList *list = (IdleConnList *)hash_lookup(table, aKey);
    if (list == NULL) {
        debugs(48, 3, "PconnPool::pop: lookup for key {" << aKey << "} failed.");
        return false;
    } else {
        debugs(48, 3, "PconnPool::pop: found " << hashKeyStr(&list->hash) << (isRetriable?"(to use)":"(to kill)") );
    }

    Comm::ConnectionPointer temp = list->findUseable(); // search from the end. skip pending reads.

    if (Comm::IsConnOpen(temp)) {
        list->clearHandlers(temp);

        /* might delete list */
        if (list->remove(temp) && !isRetriable)
            temp->close();
        else
            destLink = temp;
    }

    return true;
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
//TODO: re-link to MemPools. WAS:    pconn_fds_pool = memPoolCreate("pconn_fds", PCONN_FDS_SZ * sizeof(int));
    debugs(48, 0, "persistent connection module initialized");
    registerWithCacheManager();
}

PconnModule *
PconnModule::GetInstance()
{
    if (instance == NULL)
        instance = new PconnModule;

    return instance;
}

void
PconnModule::registerWithCacheManager(void)
{
    CacheManager::GetInstance()->
    registerAction("pconn",
                   "Persistent Connection Utilization Histograms",
                   DumpWrapper, 0, 1);
}

void

PconnModule::add(PconnPool *aPool)
{
    assert(poolCount < MAX_NUM_PCONN_POOLS);
    *(pools+poolCount) = aPool;
    poolCount++;
}

void
PconnModule::dump(StoreEntry *e)
{
    for (int i = 0; i < poolCount; i++) {
        storeAppendPrintf(e, "\n Pool %d Stats\n", i);
        (*(pools+i))->dumpHist(e);
        storeAppendPrintf(e, "\n Pool %d Hash Table\n",i);
        (*(pools+i))->dumpHash(e);
    }
}

void
PconnModule::DumpWrapper(StoreEntry *e)
{
    PconnModule::GetInstance()->dump(e);
}
