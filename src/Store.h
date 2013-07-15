/*
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

/**
 \defgroup StoreAPI  Store API
 \ingroup FileSystems
 */

#include "base/RefCount.h"
#include "comm/forward.h"
#include "CommRead.h"
#include "hash.h"
#include "HttpReply.h"
#include "HttpRequestMethod.h"
#include "Range.h"
#include "RemovalPolicy.h"
#include "StoreIOBuffer.h"
#include "StoreStats.h"

#if USE_SQUID_ESI
#include "esi/Element.h"
#endif

#if HAVE_OSTREAM
#include <ostream>
#endif

class AsyncCall;
class HttpRequest;
class MemObject;
class Packer;
class RequestFlags;
class StoreClient;
class StoreSearch;
class SwapDir;

extern StoreIoStats store_io_stats;

/// maximum number of entries per cache_dir
enum { SwapFilenMax = 0xFFFFFF }; // keep in sync with StoreEntry::swap_filen

/**
 \ingroup StoreAPI
 */
class StoreEntry : public hash_link
{

public:
    static DeferredRead::DeferrableRead DeferReader;
    bool checkDeferRead(int fd) const;

    virtual const char *getMD5Text() const;
    StoreEntry();
    StoreEntry(const char *url, const char *log_url);
    virtual ~StoreEntry();

    virtual HttpReply const *getReply() const;
    virtual void write (StoreIOBuffer);
    virtual _SQUID_INLINE_ bool isEmpty() const;
    virtual bool isAccepting() const;
    virtual size_t bytesWanted(Range<size_t> const aRange, bool ignoreDelayPool = false) const;
    virtual void complete();
    virtual store_client_t storeClientType() const;
    virtual char const *getSerialisedMetaData();
    void replaceHttpReply(HttpReply *, bool andStartWriting = true);
    void startWriting(); ///< pack and write reply headers and, maybe, body
    /// whether we may start writing to disk (now or in the future)
    virtual bool mayStartSwapOut();
    virtual void trimMemory(const bool preserveSwappable);
    void abort();
    void unlink();
    void makePublic();
    void makePrivate();
    void setPublicKey();
    void setPrivateKey();
    void expireNow();
    void releaseRequest();
    void negativeCache();
    void cacheNegatively();		/** \todo argh, why both? */
    void invokeHandlers();
    void purgeMem();
    void cacheInMemory(); ///< start or continue storing in memory cache
    void swapOut();
    /// whether we are in the process of writing this entry to disk
    bool swappingOut() const { return swap_status == SWAPOUT_WRITING; }
    void swapOutFileClose(int how);
    const char *url() const;
    int checkCachable();
    int checkNegativeHit() const;
    int locked() const;
    int validToSend() const;
    bool memoryCachable() const; ///< may be cached in memory
    void createMemObject(const char *, const char *);
    void hideMemObject(); ///< no mem_obj for callers until createMemObject
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

    void delayAwareRead(const Comm::ConnectionPointer &conn, char *buf, int len, AsyncCall::Pointer callback);

    void setNoDelay (bool const);
    bool modifiedSince(HttpRequest * request) const;
    /// has ETag matching at least one of the If-Match etags
    bool hasIfMatchEtag(const HttpRequest &request) const;
    /// has ETag matching at least one of the If-None-Match etags
    bool hasIfNoneMatchEtag(const HttpRequest &request) const;
    /// whether this entry has an ETag; if yes, puts ETag value into parameter
    bool hasEtag(ETag &etag) const;

    /** What store does this entry belong too ? */
    virtual RefCount<SwapDir> store() const;

    MemObject *mem_obj;
    MemObject *hidden_mem_obj; ///< mem_obj created before URLs were known
    RemovalPolicyNode repl;
    /* START OF ON-DISK STORE_META_STD TLV field */
    time_t timestamp;
    time_t lastref;
    time_t expires;
    time_t lastmod;
    uint64_t swap_file_sz;
    uint16_t refcount;
    uint16_t flags;
    /* END OF ON-DISK STORE_META_STD */

    /// unique ID inside a cache_dir for swapped out entries; -1 for others
    sfileno swap_filen:25; // keep in sync with SwapFilenMax

    sdirno swap_dirn:7;

    unsigned short lock_count;		/* Assume < 65536! */

    mem_status_t mem_status:3;

    ping_status_t ping_status:3;

    store_status_t store_status:3;

    swap_status_t swap_status:3;

public:
    static size_t inUseCount();
    static void getPublicByRequestMethod(StoreClient * aClient, HttpRequest * request, const HttpRequestMethod& method);
    static void getPublicByRequest(StoreClient * aClient, HttpRequest * request);
    static void getPublic(StoreClient * aClient, const char *uri, const HttpRequestMethod& method);

    virtual bool isNull() {
        return false;
    };

    void *operator new(size_t byteCount);
    void operator delete(void *address);
    void setReleaseFlag();
#if USE_SQUID_ESI

    ESIElement::Pointer cachedESITree;
#endif
    /** append bytes to the buffer */
    virtual void append(char const *, int len);
    /** disable sending content to the clients */
    virtual void buffer();
    /** flush any buffered content */
    virtual void flush();
    /** reduce the memory lock count on the entry */
    virtual int unlock();
    /** increate the memory lock count on the entry */
    virtual int64_t objectLen() const;
    virtual int64_t contentLen() const;

    virtual void lock();
    virtual void release();

#if USE_ADAPTATION
    /// call back producer when more buffer space is available
    void deferProducer(const AsyncCall::Pointer &producer);
    /// calls back producer registered with deferProducer
    void kickProducer();
#endif

private:
    static MemAllocator *pool;

#if USE_ADAPTATION
    /// producer callback registered with deferProducer
    AsyncCall::Pointer deferredProducer;
#endif

    bool validLength() const;
    bool hasOneOfEtags(const String &reqETags, const bool allowWeakMatch) const;
};

std::ostream &operator <<(std::ostream &os, const StoreEntry &e);

/// \ingroup StoreAPI
class NullStoreEntry:public StoreEntry
{

public:
    static NullStoreEntry *getInstance();
    bool isNull() {
        return true;
    }

    const char *getMD5Text() const;
    _SQUID_INLINE_ HttpReply const *getReply() const;
    void write (StoreIOBuffer) {}

    bool isEmpty () const {return true;}

    virtual size_t bytesWanted(Range<size_t> const aRange, bool ignoreDelayPool = false) const { return aRange.end; }

    void operator delete(void *address);
    void complete() {}

private:
    store_client_t storeClientType() const {return STORE_MEM_CLIENT;}

    char const *getSerialisedMetaData();
    bool mayStartSwapout() {return false;}

    void trimMemory(const bool preserveSwappable) {}

    static NullStoreEntry _instance;
};

/// \ingroup StoreAPI
typedef void (*STOREGETCLIENT) (StoreEntry *, void *cbdata);

/**
 \ingroup StoreAPI
 * Abstract base class that will replace the whole store and swapdir interface.
 */
class Store : public RefCountable
{

public:
    /** The root store */
    static _SQUID_INLINE_ Store &Root();
    static void Root(Store *);
    static void Root(RefCount<Store>);
    static void Stats(StoreEntry * output);
    static void Maintain(void *unused);

    virtual ~Store() {}

    /** Handle pending callbacks - called by the event loop. */
    virtual int callback() = 0;

    /** create the resources needed for this store to operate */
    virtual void create();

    /**
     * Notify this store that its disk is full.
     \todo XXX move into a protected api call between store files and their stores, rather than a top level api call
     */
    virtual void diskFull();

    /** Retrieve a store entry from the store */
    virtual StoreEntry * get(const cache_key *) = 0;

    /** \todo imeplement the async version */
    virtual void get(String const key , STOREGETCLIENT callback, void *cbdata) = 0;

    /* prepare the store for use. The store need not be usable immediately,
     * it should respond to readable() and writable() with true as soon
     * as it can provide those services
     */
    virtual void init() = 0;

    /**
     * The maximum size the store will support in normal use. Inaccuracy is permitted,
     * but may throw estimates for memory etc out of whack.
     */
    virtual uint64_t maxSize() const = 0;

    /** The minimum size the store will shrink to via normal housekeeping */
    virtual uint64_t minSize() const = 0;

    /** current store size */
    virtual uint64_t currentSize() const = 0;

    /** the total number of objects stored */
    virtual uint64_t currentCount() const = 0;

    /** the maximum object size that can be stored, -1 if unlimited */
    virtual int64_t maxObjectSize() const = 0;

    /// collect cache storage-related statistics
    virtual void getStats(StoreInfoStats &stats) const = 0;

    /**
     * Output stats to the provided store entry.
     \todo make these calls asynchronous
     */
    virtual void stat(StoreEntry &) const = 0;

    /** Sync the store prior to shutdown */
    virtual void sync();

    /** remove a Store entry from the store */
    virtual void unlink (StoreEntry &);

    /* search in the store */
    virtual StoreSearch *search(String const url, HttpRequest *) = 0;

    /* pulled up from SwapDir for migration.... probably do not belong here */
    virtual void reference(StoreEntry &) = 0;	/* Reference this object */

    /// Undo reference(), returning false iff idle e should be destroyed
    virtual bool dereference(StoreEntry &e, bool wantsLocalMemory) = 0;

    virtual void maintain() = 0; /* perform regular maintenance should be private and self registered ... */

    // XXX: This method belongs to Store::Root/StoreController, but it is here
    // because test cases use non-StoreController derivatives as Root
    /// called when the entry is no longer needed by any transaction
    virtual void handleIdleEntry(StoreEntry &e) {}

    // XXX: This method belongs to Store::Root/StoreController, but it is here
    // because test cases use non-StoreController derivatives as Root
    /// called to get rid of no longer needed entry data in RAM, if any
    virtual void maybeTrimMemory(StoreEntry &e, const bool preserveSwappable) {}

private:
    static RefCount<Store> CurrentRoot;
};

/// \ingroup StoreAPI
typedef RefCount<Store> StorePointer;

/// \ingroup StoreAPI
size_t storeEntryInUse();

/// \ingroup StoreAPI
const char *storeEntryFlags(const StoreEntry *);

/// \ingroup StoreAPI
void storeEntryReplaceObject(StoreEntry *, HttpReply *);

/// \ingroup StoreAPI
StoreEntry *storeGetPublic(const char *uri, const HttpRequestMethod& method);

/// \ingroup StoreAPI
StoreEntry *storeGetPublicByRequest(HttpRequest * request);

/// \ingroup StoreAPI
StoreEntry *storeGetPublicByRequestMethod(HttpRequest * request, const HttpRequestMethod& method);

/// \ingroup StoreAPI
StoreEntry *storeCreateEntry(const char *, const char *, const RequestFlags &, const HttpRequestMethod&);

/// \ingroup StoreAPI
void storeInit(void);

/// \ingroup StoreAPI
void storeConfigure(void);

/// \ingroup StoreAPI
void storeFreeMemory(void);

/// \ingroup StoreAPI
int expiresMoreThan(time_t, time_t);

/// \ingroup StoreAPI
void storeAppendPrintf(StoreEntry *, const char *,...) PRINTF_FORMAT_ARG2;

/// \ingroup StoreAPI
void storeAppendVPrintf(StoreEntry *, const char *, va_list ap);

/// \ingroup StoreAPI
int storeTooManyDiskFilesOpen(void);

class SwapDir;
/// \ingroup StoreAPI
void storeHeapPositionUpdate(StoreEntry *, SwapDir *);

/// \ingroup StoreAPI
void storeSwapFileNumberSet(StoreEntry * e, sfileno filn);

/// \ingroup StoreAPI
void storeFsInit(void);

/// \ingroup StoreAPI
void storeFsDone(void);

/// \ingroup StoreAPI
void storeReplAdd(const char *, REMOVALPOLICYCREATE *);

/// \ingroup StoreAPI
extern FREE destroyStoreEntry;

/**
 \ingroup StoreAPI
 \todo should be a subclass of Packer perhaps ?
 */
void packerToStoreInit(Packer * p, StoreEntry * e);

/// \ingroup StoreAPI
void storeGetMemSpace(int size);

#if _USE_INLINE_
#include "Store.cci"
#endif

#endif /* SQUID_STORE_H */
