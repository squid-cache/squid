/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 48    Persistent Connections */

#include "squid.h"
#include "comm/Connection.h"
#include "comm/Flag.h"
#include "comm/IdleConnList.h"
#include "comm/Read.h"
#include "fde.h"
#include "pconn.h"
#include "SquidConfig.h"

#define PCONN_FDS_SZ    8   /* pconn set size, increase for better memcache hit rate */

CBDATA_CLASS_INIT(IdleConnList);

IdleConnList::IdleConnList(const char *aKey, PconnPool *thePool) :
    capacity_(PCONN_FDS_SZ),
    size_(0),
    parent_(thePool)
{
    //Initialize hash_link members
    key = xstrdup(aKey);
    next = nullptr;

    theList_ = new Comm::ConnectionPointer[capacity_];

    registerRunner();

// TODO: re-attach to MemPools. WAS: theList = (?? *)pconn_fds_pool->alloc();
}

IdleConnList::~IdleConnList()
{
    if (parent_)
        parent_->unlinkList(this);

    if (size_) {
        parent_ = nullptr; // prevent reentrant notifications and deletions
        closeN(size_);
    }

    delete[] theList_;
    xfree(key);
}

/** Search the list. Matches by FD socket number.
 * Performed from the end of list where newest entries are.
 *
 * \retval <0   The connection is not listed
 * \retval >=0  The connection array index
 */
int
IdleConnList::findIndexOf(const Comm::ConnectionPointer &conn) const
{
    for (auto right = size_; right > 0; --right) {
        const auto index = right - 1;
        if (conn->fd == theList_[index]->fd) {
            debugs(48, 3, "found " << conn << " at index " << index);
            return index;
        }
    }

    debugs(48, 2, conn << " NOT FOUND!");
    return -1;
}

/** Remove the entry at specified index.
 * May perform a shuffle of list entries to fill the gap.
 * \retval false The index is not an in-use entry.
 */
bool
IdleConnList::removeAt(size_t index)
{
    if (index >= size_)
        return false;
    assert(size_ > 0);

    // shuffle the remaining entries to fill the new gap.
    for (; index < size_ - 1; ++index)
        theList_[index] = theList_[index + 1];
    theList_[--size_] = nullptr;

    if (parent_) {
        parent_->noteConnectionRemoved();
        if (size_ == 0) {
            debugs(48, 3, "deleting " << hashKeyStr(this));
            delete this;
        }
    }

    return true;
}

// almost a duplicate of removeFD. But drops multiple entries.
void
IdleConnList::closeN(const size_t n)
{
    if (n < 1) {
        debugs(48, 2, "Nothing to do.");
        return;
    } else if (n >= size_) {
        debugs(48, 2, "Closing all entries.");
        while (size_ > 0) {
            const Comm::ConnectionPointer conn = theList_[--size_];
            theList_[size_] = nullptr;
            clearHandlers(conn);
            conn->close();
            if (parent_)
                parent_->noteConnectionRemoved();
        }
    } else { //if (n < size_)
        debugs(48, 2, "Closing " << n << " of " << size_ << " entries.");

        size_t index;
        // ensure the first N entries are closed
        for (index = 0; index < n; ++index) {
            const Comm::ConnectionPointer conn = theList_[index];
            theList_[index] = nullptr;
            clearHandlers(conn);
            conn->close();
            if (parent_)
                parent_->noteConnectionRemoved();
        }
        // shuffle the list N down.
        for (index = 0; index < size_ - n; ++index) {
            theList_[index] = theList_[index + n];
        }
        // ensure the last N entries are unset
        while (index < size_) {
            theList_[index] = nullptr;
            ++index;
        }
        size_ -= n;
    }

    if (parent_ && size_ == 0) {
        debugs(48, 3, "deleting " << hashKeyStr(this));
        delete this;
    }
}

void
IdleConnList::clearHandlers(const Comm::ConnectionPointer &conn)
{
    debugs(48, 3, "removing close handler for " << conn);
    comm_read_cancel(conn->fd, IdleConnList::Read, this);
    commUnsetConnTimeout(conn);
}

void
IdleConnList::push(const Comm::ConnectionPointer &conn)
{
    if (size_ == capacity_) {
        debugs(48, 3, "growing idle Connection array");
        capacity_ <<= 1;
        const Comm::ConnectionPointer *oldList = theList_;
        theList_ = new Comm::ConnectionPointer[capacity_];
        for (size_t index = 0; index < size_; ++index)
            theList_[index] = oldList[index];

        delete[] oldList;
    }

    if (parent_)
        parent_->noteConnectionAdded();

    theList_[size_] = conn;
    ++size_;
    AsyncCall::Pointer readCall = commCbCall(5,4, "IdleConnList::Read",
                                  CommIoCbPtrFun(IdleConnList::Read, this));
    comm_read(conn, fakeReadBuf_, sizeof(fakeReadBuf_), readCall);
    AsyncCall::Pointer timeoutCall = commCbCall(5,4, "IdleConnList::Timeout",
                                     CommTimeoutCbPtrFun(IdleConnList::Timeout, this));
    commSetConnTimeout(conn, conn->timeLeft(Config.Timeout.serverIdlePconn), timeoutCall);
}

/// Determine whether an entry in the idle list is available for use.
/// Returns false if the entry is unset, closed or closing.
bool
IdleConnList::isAvailable(int i) const
{
    const Comm::ConnectionPointer &conn = theList_[i];

    // connection already closed. useless.
    if (!Comm::IsConnOpen(conn))
        return false;

    // our connection early-read/close handler is scheduled to run already. unsafe
    if (!COMMIO_FD_READCB(conn->fd)->active())
        return false;

    return true;
}

Comm::ConnectionPointer
IdleConnList::pop()
{
    for (auto right = size_; right > 0; --right) {
        const auto i = right - 1;

        if (!isAvailable(i))
            continue;

        // our connection timeout handler is scheduled to run already. unsafe for now.
        // TODO: cancel the pending timeout callback and allow reuse of the conn.
        if (fd_table[theList_[i]->fd].timeoutHandler == nullptr)
            continue;

        // the cache_peer has been removed from the configuration
        // TODO: remove all such connections at once during reconfiguration
        if (theList_[i]->toGoneCachePeer())
            continue;

        // finally, a match. pop and return it.
        Comm::ConnectionPointer result = theList_[i];
        clearHandlers(result);
        /* may delete this */
        removeAt(i);
        return result;
    }

    return Comm::ConnectionPointer();
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
IdleConnList::findUseable(const Comm::ConnectionPointer &aKey)
{
    assert(size_);

    // small optimization: do the constant bool tests only once.
    const bool keyCheckAddr = !aKey->local.isAnyAddr();
    const bool keyCheckPort = aKey->local.port() > 0;

    for (auto right = size_; right > 0; --right) {
        const auto i = right - 1;

        if (!isAvailable(i))
            continue;

        // local end port is required, but do not match.
        if (keyCheckPort && aKey->local.port() != theList_[i]->local.port())
            continue;

        // local address is required, but does not match.
        if (keyCheckAddr && aKey->local.matchIPAddr(theList_[i]->local) != 0)
            continue;

        // our connection timeout handler is scheduled to run already. unsafe for now.
        // TODO: cancel the pending timeout callback and allow reuse of the conn.
        if (fd_table[theList_[i]->fd].timeoutHandler == nullptr)
            continue;

        // the cache_peer has been removed from the configuration
        // TODO: remove all such connections at once during reconfiguration
        if (theList_[i]->toGoneCachePeer())
            continue;

        // finally, a match. pop and return it.
        Comm::ConnectionPointer result = theList_[i];
        clearHandlers(result);
        /* may delete this */
        removeAt(i);
        return result;
    }

    return Comm::ConnectionPointer();
}

/* might delete list */
void
IdleConnList::findAndClose(const Comm::ConnectionPointer &conn)
{
    const int index = findIndexOf(conn);
    if (index >= 0) {
        if (parent_)
            parent_->notifyManager("idle conn closure");
        clearHandlers(conn);
        /* might delete this */
        removeAt(index);
        conn->close();
    }
}

void
IdleConnList::Read(const Comm::ConnectionPointer &conn, char *, size_t len, Comm::Flag flag, int, void *data)
{
    debugs(48, 3, len << " bytes from " << conn);

    if (flag == Comm::ERR_CLOSING) {
        debugs(48, 3, "Comm::ERR_CLOSING from " << conn);
        /* Bail out on Comm::ERR_CLOSING - may happen when shutdown aborts our idle FD */
        return;
    }

    IdleConnList *list = (IdleConnList *) data;
    /* may delete list/data */
    list->findAndClose(conn);
}

void
IdleConnList::Timeout(const CommTimeoutCbParams &io)
{
    debugs(48, 3, io.conn);
    IdleConnList *list = static_cast<IdleConnList *>(io.data);
    /* may delete list/data */
    list->findAndClose(io.conn);
}

void
IdleConnList::endingShutdown()
{
    closeN(size_);
}
