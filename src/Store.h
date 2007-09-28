
/*
 * $Id: Store.h,v 1.37 2007/09/28 00:22:37 hno Exp $
 *
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

#ifndef SQUID_STORE_H
#define SQUID_STORE_H

#include "squid.h"

#include <ostream>

#include "StoreIOBuffer.h"
#include "Range.h"
#include "RefCount.h"
#include "CommRead.h"
#include "Packer.h"
#include "RemovalPolicy.h"

#if ESI
#include "ESIElement.h"
#endif

class StoreClient;

class MemObject;

class Store;

class StoreSearch;

class StoreEntry : public hash_link
{

public:
    static DeferredRead::DeferrableRead DeferReader;
    bool checkDeferRead(int fd) const;

    virtual const char *getMD5Text() const;
    StoreEntry();
    StoreEntry(const char *url, const char *log_url);
    virtual ~StoreEntry(){}

    virtual HttpReply const *getReply() const;
    virtual void write (StoreIOBuffer);
    virtual _SQUID_INLINE_ bool isEmpty() const;
    virtual bool isAccepting() const;
    virtual size_t bytesWanted(Range<size_t> const) const;
    virtual void complete();
    virtual store_client_t storeClientType() const;
    virtual char const *getSerialisedMetaData();
    virtual void replaceHttpReply(HttpReply *);
    virtual bool swapoutPossible();
    virtual void trimMemory();
    void abort();
    void unlink();
    void makePublic();
    void makePrivate();
    void setPublicKey();
    void setPrivateKey();
    void expireNow();
    void releaseRequest();
    void negativeCache();
    void cacheNegatively();		/* argh, why both? */
    void invokeHandlers();
    void purgeMem();
    void swapOut();
    bool swapOutAble() const;
    void swapOutFileClose();
    const char *url() const;
    int checkCachable();
    int checkNegativeHit() const;
    int locked() const;
    int validToSend() const;
    int keepInMemory() const;
    void createMemObject(const char *, const char *);
    void dump(int debug_lvl) const;
    void hashDelete();
    void hashInsert(const cache_key *);
    void registerAbort(STABH * cb, void *);
    void reset();
    void setMemStatus(mem_status_t);
    void timestampsSet();
    void unregisterAbort();
    void destroyMemObject();
    int checkTooSmall();

    void delayAwareRead(int fd, char *buf, int len, IOCB *handler, void *data);

    void setNoDelay (bool const);
    bool modifiedSince(HttpRequest * request) const;
    /* what store does this entry belong too ? */
    virtual RefCount<Store> store() const;

    MemObject *mem_obj;
    RemovalPolicyNode repl;
    /* START OF ON-DISK STORE_META_STD TLV field */
    time_t timestamp;
    time_t lastref;
    time_t expires;
    time_t lastmod;
    uint64_t swap_file_sz;
    u_short refcount;
    u_short flags;
    /* END OF ON-DISK STORE_META_STD */

sfileno swap_filen:
    25;

sdirno swap_dirn:
    7;
    u_short lock_count;		/* Assume < 65536! */

mem_status_t mem_status:
    3;

ping_status_t ping_status:
    3;

store_status_t store_status:
    3;

swap_status_t swap_status:
    3;

public:
    static size_t inUseCount();
    static void getPublicByRequestMethod(StoreClient * aClient, HttpRequest * request, const method_t method);
    static void getPublicByRequest(StoreClient * aClient, HttpRequest * request);
    static void getPublic(StoreClient * aClient, const char *uri, const method_t method);

    virtual bool isNull()
    {
        return false;
    }

    void *operator new(size_t byteCount);
    void operator delete(void *address);
    void setReleaseFlag();
#if ESI

    ESIElement::Pointer cachedESITree;
#endif
    /* append bytes to the buffer */
    virtual void append(char const *, int len);
    /* disable sending content to the clients */
    virtual void buffer();
    /* flush any buffered content */
    virtual void flush();
    /* reduce the memory lock count on the entry */
    virtual int unlock();
    /* increate the memory lock count on the entry */
    virtual int64_t objectLen() const;
    virtual int64_t contentLen() const;

    virtual void lock()

        ;
    virtual void release();

private:
    static MemAllocator *pool;

    bool validLength() const;
};

class NullStoreEntry:public StoreEntry
{

public:
    static NullStoreEntry *getInstance();
    bool isNull()
    {
        return true;
    }

    const char *getMD5Text() const;
    _SQUID_INLINE_ HttpReply const *getReply() const;
    void write (StoreIOBuffer){}

    bool isEmpty () const {return true;}

    virtual size_t bytesWanted(Range<size_t> const aRange) const { assert (aRange.size());return aRange.end - 1;}

    void operator delete(void *address);
    void complete(){}

private:
    store_client_t storeClientType() const{return STORE_MEM_CLIENT;}

    char const *getSerialisedMetaData();
    bool swapoutPossible() {return false;}

    void trimMemory() {}


    static NullStoreEntry _instance;
};

typedef void (*STOREGETCLIENT) (StoreEntry *, void *cbdata);


/* Abstract base class that will replace the whole store and swapdir interface. */

class Store : public RefCountable
{

public:
    /* The root store */
    static _SQUID_INLINE_ Store &Root();
    static void Root(Store *);
    static void Root(RefCount<Store>);
    static void Stats(StoreEntry * output);
    static void Maintain(void *unused);

    virtual ~Store() {}

    /* Handle pending callbacks - called by the event loop. */
    virtual int callback() = 0;
    /* create the resources needed for this store to operate */
    virtual void create();
    /* notify this store that its disk is full. TODO XXX move into a protected api call
     * between store files and their stores, rather than a top level api call
     */
    virtual void diskFull();
    /* Retrieve a store entry from the store */

    virtual StoreEntry * get
        (const cache_key *) = 0;

    /* TODO: imeplement the async version */
    virtual void get
        (String const key , STOREGETCLIENT callback, void *cbdata) = 0;

    /* prepare the store for use. The store need not be usable immediately,
     * it should respond to readable() and writable() with true as soon
     * as it can provide those services
     */
    virtual void init() = 0;

    /* the maximum size the store will support in normal use. Inaccuracy is permitted,
     * but may throw estimates for memory etc out of whack. */
    virtual size_t maxSize() const = 0;

    /* The minimum size the store will shrink to via normal housekeeping */
    virtual size_t minSize() const = 0;

    /* TODO: make these calls asynchronous */
    virtual void stat(StoreEntry &) const = 0; /* output stats to the provided store entry */

    virtual void sync();	/* Sync the store prior to shutdown */

    /* remove a Store entry from the store */
    virtual void unlink (StoreEntry &);

    /* search in the store */
    virtual StoreSearch *search(String const url, HttpRequest *) = 0;

    /* pulled up from SwapDir for migration.... probably do not belong here */
    virtual void reference(StoreEntry &) = 0;	/* Reference this object */

    virtual void dereference(StoreEntry &) = 0;	/* Unreference this object */

    virtual void maintain() = 0; /* perform regular maintenance should be private and self registered ... */

    /* These should really be private */
    virtual void updateSize(int64_t size, int sign) = 0;

private:
    static RefCount<Store> CurrentRoot;
};

typedef RefCount<Store> StorePointer;

SQUIDCEXTERN size_t storeEntryInUse();
#if UNUSED_CODE_20070420
SQUIDCEXTERN off_t storeLowestMemReaderOffset(const StoreEntry * entry);
#endif
SQUIDCEXTERN const char *storeEntryFlags(const StoreEntry *);
extern void storeEntryReplaceObject(StoreEntry *, HttpReply *);

SQUIDCEXTERN StoreEntry *storeGetPublic(const char *uri, const method_t method);
SQUIDCEXTERN StoreEntry *storeGetPublicByRequest(HttpRequest * request);
SQUIDCEXTERN StoreEntry *storeGetPublicByRequestMethod(HttpRequest * request, const method_t method);
SQUIDCEXTERN StoreEntry *storeCreateEntry(const char *, const char *, request_flags, method_t);
SQUIDCEXTERN void storeInit(void);
extern void storeRegisterWithCacheManager(CacheManager & manager);
SQUIDCEXTERN void storeConfigure(void);
SQUIDCEXTERN void storeFreeMemory(void);
SQUIDCEXTERN int expiresMoreThan(time_t, time_t);
#if STDC_HEADERS
SQUIDCEXTERN void
storeAppendPrintf(StoreEntry *, const char *,...) PRINTF_FORMAT_ARG2;
#else
SQUIDCEXTERN void storeAppendPrintf();
#endif
SQUIDCEXTERN void storeAppendVPrintf(StoreEntry *, const char *, va_list ap);
SQUIDCEXTERN int storeTooManyDiskFilesOpen(void);
SQUIDCEXTERN void storeHeapPositionUpdate(StoreEntry *, SwapDir *);
SQUIDCEXTERN void storeSwapFileNumberSet(StoreEntry * e, sfileno filn);
SQUIDCEXTERN void storeFsInit(void);
SQUIDCEXTERN void storeFsDone(void);
SQUIDCEXTERN void storeReplAdd(const char *, REMOVALPOLICYCREATE *);
extern FREE destroyStoreEntry;

/* should be a subclass of Packer perhaps ? */
SQUIDCEXTERN void packerToStoreInit(Packer * p, StoreEntry * e);

#ifdef _USE_INLINE_
#include "Store.cci"
#endif

#endif /* SQUID_STORE_H */
