/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORE_H
#define SQUID_STORE_H

#include "base/Packable.h"
#include "base/RefCount.h"
#include "comm/forward.h"
#include "CommRead.h"
#include "hash.h"
#include "http/forward.h"
#include "http/RequestMethod.h"
#include "HttpReply.h"
#include "MemObject.h"
#include "Range.h"
#include "RemovalPolicy.h"
#include "store/Controller.h"
#include "store/forward.h"
#include "store_key_md5.h"
#include "StoreIOBuffer.h"
#include "StoreStats.h"

#if USE_SQUID_ESI
#include "esi/Element.h"
#endif

#include <ostream>

class AsyncCall;
class HttpRequest;
class RequestFlags;

extern StoreIoStats store_io_stats;

class StoreEntry : public hash_link, public Packable
{

public:
    static DeferredRead::DeferrableRead DeferReader;
    bool checkDeferRead(int fd) const;

    virtual const char *getMD5Text() const;
    StoreEntry();
    virtual ~StoreEntry();

    virtual HttpReply const *getReply() const;
    virtual void write (StoreIOBuffer);

    /** Check if the Store entry is emtpty
     * \retval true   Store contains 0 bytes of data.
     * \retval false  Store contains 1 or more bytes of data.
     * \retval false  Store contains negative content !!!!!!
     */
    virtual bool isEmpty() const {
        assert (mem_obj);
        return mem_obj->endOffset() == 0;
    }
    virtual bool isAccepting() const;
    virtual size_t bytesWanted(Range<size_t> const aRange, bool ignoreDelayPool = false) const;
    /// flags [truncated or too big] entry with ENTRY_BAD_LENGTH and releases it
    void lengthWentBad(const char *reason);
    virtual void complete();
    virtual store_client_t storeClientType() const;
    virtual char const *getSerialisedMetaData();
    /// Store a prepared error response. MemObject locks the reply object.
    void storeErrorResponse(HttpReply *reply);
    void replaceHttpReply(HttpReply *, bool andStartWriting = true);
    void startWriting(); ///< pack and write reply headers and, maybe, body
    /// whether we may start writing to disk (now or in the future)
    virtual bool mayStartSwapOut();
    virtual void trimMemory(const bool preserveSwappable);

    // called when a decision to cache in memory has been made
    void memOutDecision(const bool willCacheInRam);
    // called when a decision to cache on disk has been made
    void swapOutDecision(const MemObject::SwapOut::Decision &decision);

    void abort();
    void makePublic(const KeyScope keyScope = ksDefault);
    void makePrivate(const bool shareable);
    /// A low-level method just resetting "private key" flags.
    /// To avoid key inconsistency please use forcePublicKey()
    /// or similar instead.
    void clearPrivate();
    void setPublicKey(const KeyScope keyScope = ksDefault);
    /// Resets existing public key to a public key with default scope,
    /// releasing the old default-scope entry (if any).
    /// Does nothing if the existing public key already has default scope.
    void clearPublicKeyScope();
    void setPrivateKey(const bool shareable);
    void expireNow();
    void releaseRequest(const bool shareable = false);
    void negativeCache();
    void cacheNegatively();     /** \todo argh, why both? */
    void invokeHandlers();
    void purgeMem();
    void cacheInMemory(); ///< start or continue storing in memory cache
    void swapOut();
    /// whether we are in the process of writing this entry to disk
    bool swappingOut() const { return swap_status == SWAPOUT_WRITING; }
    void swapOutFileClose(int how);
    const char *url() const;
    /// Satisfies cachability requirements shared among disk and RAM caches.
    /// Encapsulates common checks of mayStartSwapOut() and memoryCachable().
    /// TODO: Rename and make private so only those two methods can call this.
    bool checkCachable();
    int checkNegativeHit() const;
    int locked() const;
    int validToSend() const;
    bool memoryCachable(); ///< checkCachable() and can be cached in memory

    /// if needed, initialize mem_obj member w/o URI-related information
    MemObject *makeMemObject();

    /// initialize mem_obj member (if needed) and supply URI-related info
    void createMemObject(const char *storeId, const char *logUri, const HttpRequestMethod &aMethod);

    void dump(int debug_lvl) const;
    void hashDelete();
    void hashInsert(const cache_key *);
    void registerAbort(STABH * cb, void *);
    void reset();
    void setMemStatus(mem_status_t);
    bool timestampsSet();
    void unregisterAbort();
    void destroyMemObject();
    int checkTooSmall();

    void delayAwareRead(const Comm::ConnectionPointer &conn, char *buf, int len, AsyncCall::Pointer callback);

    void setNoDelay (bool const);
    void lastModified(const time_t when) { lastModified_ = when; }
    /// \returns entry's 'effective' modification time
    time_t lastModified() const {
        // may still return -1 if timestamp is not set
        return lastModified_ < 0 ? timestamp : lastModified_;
    }
    /// \returns a formatted string with entry's timestamps
    const char *describeTimestamps() const;
    // TODO: consider removing currently unsupported imslen parameter
    bool modifiedSince(const time_t ims, const int imslen = -1) const;
    /// has ETag matching at least one of the If-Match etags
    bool hasIfMatchEtag(const HttpRequest &request) const;
    /// has ETag matching at least one of the If-None-Match etags
    bool hasIfNoneMatchEtag(const HttpRequest &request) const;
    /// whether this entry has an ETag; if yes, puts ETag value into parameter
    bool hasEtag(ETag &etag) const;

    /// the disk this entry is [being] cached on; asserts for entries w/o a disk
    Store::Disk &disk() const;

    MemObject *mem_obj;
    RemovalPolicyNode repl;
    /* START OF ON-DISK STORE_META_STD TLV field */
    time_t timestamp;
    time_t lastref;
    time_t expires;
private:
    time_t lastModified_; ///< received Last-Modified value or -1; use lastModified()
public:
    uint64_t swap_file_sz;
    uint16_t refcount;
    uint16_t flags;
    /* END OF ON-DISK STORE_META_STD */

    /// unique ID inside a cache_dir for swapped out entries; -1 for others
    sfileno swap_filen:25; // keep in sync with SwapFilenMax

    sdirno swap_dirn:7;

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
    virtual int64_t objectLen() const;
    virtual int64_t contentLen() const;

    /// claim shared ownership of this entry (for use in a given context)
    /// matching lock() and unlock() contexts eases leak triage but is optional
    void lock(const char *context);

    /// disclaim shared ownership; may remove entry from store and delete it
    /// returns remaning lock level (zero for unlocked and possibly gone entry)
    int unlock(const char *context);

    /// returns a local concurrent use counter, for debugging
    int locks() const { return static_cast<int>(lock_count); }

    /// update last reference timestamp and related Store metadata
    void touch();

    virtual void release(const bool shareable = false);

    /// May the caller commit to treating this [previously locked]
    /// entry as a cache hit?
    bool mayStartHitting() const {
        return !EBIT_TEST(flags, KEY_PRIVATE) || shareableWhenPrivate;
    }

#if USE_ADAPTATION
    /// call back producer when more buffer space is available
    void deferProducer(const AsyncCall::Pointer &producer);
    /// calls back producer registered with deferProducer
    void kickProducer();
#endif

    /* Packable API */
    virtual void append(char const *, int);
    virtual void vappendf(const char *, va_list);
    virtual void buffer();
    virtual void flush();

protected:
    void transientsAbandonmentCheck();

private:
    bool checkTooBig() const;
    void forcePublicKey(const cache_key *newkey);
    void adjustVary();
    const cache_key *calcPublicKey(const KeyScope keyScope);

    static MemAllocator *pool;

    unsigned short lock_count;      /* Assume < 65536! */

    /// Nobody can find/lock KEY_PRIVATE entries, but some transactions
    /// (e.g., collapsed requests) find/lock a public entry before it becomes
    /// private. May such transactions start using the now-private entry
    /// they previously locked? This member should not affect transactions
    /// that already started reading from the entry.
    bool shareableWhenPrivate;

#if USE_ADAPTATION
    /// producer callback registered with deferProducer
    AsyncCall::Pointer deferredProducer;
#endif

    bool validLength() const;
    bool hasOneOfEtags(const String &reqETags, const bool allowWeakMatch) const;

    friend std::ostream &operator <<(std::ostream &os, const StoreEntry &e);
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
    HttpReply const *getReply() const { return NULL; }
    void write (StoreIOBuffer) {}

    bool isEmpty () const {return true;}

    virtual size_t bytesWanted(Range<size_t> const aRange, bool) const { return aRange.end; }

    void operator delete(void *address);
    void complete() {}

private:
    store_client_t storeClientType() const {return STORE_MEM_CLIENT;}

    char const *getSerialisedMetaData();
    virtual bool mayStartSwapOut() { return false; }

    void trimMemory(const bool) {}

    static NullStoreEntry _instance;
};

/// \ingroup StoreAPI
typedef void (*STOREGETCLIENT) (StoreEntry *, void *cbdata);

namespace Store {
void Stats(StoreEntry *output);
void Maintain(void *unused);
};

/// \ingroup StoreAPI
size_t storeEntryInUse();

/// \ingroup StoreAPI
const char *storeEntryFlags(const StoreEntry *);

/// \ingroup StoreAPI
void storeEntryReplaceObject(StoreEntry *, HttpReply *);

/// \ingroup StoreAPI
StoreEntry *storeGetPublic(const char *uri, const HttpRequestMethod& method);

/// \ingroup StoreAPI
StoreEntry *storeGetPublicByRequest(HttpRequest * request, const KeyScope keyScope = ksDefault);

/// \ingroup StoreAPI
StoreEntry *storeGetPublicByRequestMethod(HttpRequest * request, const HttpRequestMethod& method, const KeyScope keyScope = ksDefault);

/// \ingroup StoreAPI
/// Like storeCreatePureEntry(), but also locks the entry and sets entry key.
StoreEntry *storeCreateEntry(const char *, const char *, const RequestFlags &, const HttpRequestMethod&);

/// \ingroup StoreAPI
/// Creates a new StoreEntry with mem_obj and sets initial flags/states.
StoreEntry *storeCreatePureEntry(const char *storeId, const char *logUrl, const RequestFlags &, const HttpRequestMethod&);

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

/// \ingroup StoreAPI
void storeGetMemSpace(int size);

#endif /* SQUID_STORE_H */

