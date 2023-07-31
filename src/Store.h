/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORE_H
#define SQUID_STORE_H

#include "base/DelayedAsyncCalls.h"
#include "base/Packable.h"
#include "base/Range.h"
#include "base/RefCount.h"
#include "comm/forward.h"
#include "hash.h"
#include "http/forward.h"
#include "http/RequestMethod.h"
#include "HttpReply.h"
#include "MemObject.h"
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
    bool checkDeferRead(int fd) const;

    const char *getMD5Text() const;
    StoreEntry();
    ~StoreEntry() override;

    MemObject &mem() { assert(mem_obj); return *mem_obj; }
    const MemObject &mem() const { assert(mem_obj); return *mem_obj; }

    /// \retval * the address of freshest reply (if mem_obj exists)
    /// \retval nullptr when mem_obj does not exist
    /// \see MemObject::freshestReply()
    const HttpReply *hasFreshestReply() const { return mem_obj ? &mem_obj->freshestReply() : nullptr; }

    void write(StoreIOBuffer);

    /** Check if the Store entry is empty
     * \retval true   Store contains 0 bytes of data.
     * \retval false  Store contains 1 or more bytes of data.
     * \retval false  Store contains negative content !!!!!!
     */
    bool isEmpty() const { return mem().endOffset() == 0; }
    bool isAccepting() const;
    size_t bytesWanted(Range<size_t> const aRange, bool ignoreDelayPool = false) const;

    /// Signals that the entire response has been stored and no more append()
    /// calls should be expected; cf. completeTruncated().
    void completeSuccessfully(const char *whyWeAreSureWeStoredTheWholeReply);

    /// Signals that a partial response (if any) has been stored but no more
    /// append() calls should be expected; cf. completeSuccessfully().
    void completeTruncated(const char *whyWeConsiderTheReplyTruncated);

    /// \deprecated use either completeSuccessfully() or completeTruncated() instead
    void complete();

    store_client_t storeClientType() const;
    /// \returns a malloc()ed buffer containing a length-long packed swap header
    const char *getSerialisedMetaData(size_t &length) const;
    /// Store a prepared error response. MemObject locks the reply object.
    void storeErrorResponse(HttpReply *reply);
    void replaceHttpReply(const HttpReplyPointer &, const bool andStartWriting = true);
    void startWriting(); ///< pack and write reply headers and, maybe, body
    /// whether we may start writing to disk (now or in the future)
    bool mayStartSwapOut();
    void trimMemory(const bool preserveSwappable);

    // called when a decision to cache in memory has been made
    void memOutDecision(const bool willCacheInRam);
    // called when a decision to cache on disk has been made
    void swapOutDecision(const MemObject::SwapOut::Decision &decision);
    /// called when a store writer ends its work (successfully or not)
    void storeWriterDone();

    void abort();
    bool makePublic(const KeyScope keyScope = ksDefault);
    void makePrivate(const bool shareable);
    /// A low-level method just resetting "private key" flags.
    /// To avoid key inconsistency please use forcePublicKey()
    /// or similar instead.
    void clearPrivate();
    bool setPublicKey(const KeyScope keyScope = ksDefault);
    /// Resets existing public key to a public key with default scope,
    /// releasing the old default-scope entry (if any).
    /// Does nothing if the existing public key already has default scope.
    void clearPublicKeyScope();

    /// \returns public key (if the entry has it) or nil (otherwise)
    const cache_key *publicKey() const {
        return (!EBIT_TEST(flags, KEY_PRIVATE)) ?
               reinterpret_cast<const cache_key*>(key): // may be nil
               nullptr;
    }

    /// Either fills this entry with private key or changes the existing key
    /// from public to private.
    /// \param permanent whether this entry should be private forever.
    void setPrivateKey(const bool shareable, const bool permanent);

    void expireNow();
    /// Makes the StoreEntry private and marks the corresponding entry
    /// for eventual removal from the Store.
    void releaseRequest(const bool shareable = false);
    void negativeCache();
    bool cacheNegatively();     // TODO: why both negativeCache() and cacheNegatively() ?
    void invokeHandlers();
    void cacheInMemory(); ///< start or continue storing in memory cache
    void swapOut();
    /// whether we are in the process of writing this entry to disk
    bool swappingOut() const { return swap_status == SWAPOUT_WRITING; }
    /// whether the entire entry is now on disk (possibly marked for deletion)
    bool swappedOut() const { return swap_status == SWAPOUT_DONE; }
    /// whether we failed to write this entry to disk
    bool swapoutFailed() const { return swap_status == SWAPOUT_FAILED; }
    void swapOutFileClose(int how);
    const char *url() const;
    /// Satisfies cachability requirements shared among disk and RAM caches.
    /// Encapsulates common checks of mayStartSwapOut() and memoryCachable().
    /// TODO: Rename and make private so only those two methods can call this.
    bool checkCachable();
    int checkNegativeHit() const;
    int locked() const { return lock_count; }
    int validToSend() const;
    bool memoryCachable(); ///< checkCachable() and can be cached in memory

    /// initialize mem_obj; assert if mem_obj already exists
    /// avoid this method in favor of createMemObject(trio)!
    void createMemObject();

    /// initialize mem_obj with URIs/method; assert if mem_obj already exists
    void createMemObject(const char *storeId, const char *logUri, const HttpRequestMethod &aMethod);

    /// initialize mem_obj (if needed) and set URIs/method (if missing)
    void ensureMemObject(const char *storeId, const char *logUri, const HttpRequestMethod &aMethod);

    void dump(int debug_lvl) const;
    void hashDelete();
    void hashInsert(const cache_key *);
    /// notify the StoreEntry writer of a 3rd-party initiated StoreEntry abort
    void registerAbortCallback(const AsyncCall::Pointer &);
    void reset();
    void setMemStatus(mem_status_t);
    bool timestampsSet();
    /// Avoid notifying anybody about a 3rd-party initiated StoreEntry abort.
    /// Calling this method does not cancel the already queued notification.
    /// TODO: Refactor to represent the end of (shared) ownership by our writer.
    void unregisterAbortCallback(const char *reason);
    void destroyMemObject();
    int checkTooSmall();

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

    /// Updates easily-accessible non-Store-specific parts of the entry.
    /// Use Controller::updateOnNotModified() instead of this helper.
    /// \returns whether anything was actually updated
    bool updateOnNotModified(const StoreEntry &e304);

    /// the disk this entry is [being] cached on; asserts for entries w/o a disk
    Store::Disk &disk() const;
    /// whether one of this StoreEntry owners has locked the corresponding
    /// disk entry (at the specified disk entry coordinates, if any)
    bool hasDisk(const sdirno dirn = -1, const sfileno filen = -1) const;
    /// Makes hasDisk(dirn, filn) true. The caller should have locked
    /// the corresponding disk store entry for reading or writing.
    void attachToDisk(const sdirno, const sfileno, const swap_status_t);
    /// Makes hasDisk() false. The caller should have unlocked
    /// the corresponding disk store entry.
    void detachFromDisk();

    /// whether there is a corresponding locked transients table entry
    bool hasTransients() const { return mem_obj && mem_obj->xitTable.index >= 0; }
    /// whether there is a corresponding locked shared memory table entry
    bool hasMemStore() const { return mem_obj && mem_obj->memCache.index >= 0; }

    /// whether this entry can feed collapsed requests and only them
    bool hittingRequiresCollapsing() const { return EBIT_TEST(flags, ENTRY_REQUIRES_COLLAPSING); }

    /// allow or forbid collapsed requests feeding
    void setCollapsingRequirement(const bool required);

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

    void *operator new(size_t byteCount);
    void operator delete(void *address);
#if USE_SQUID_ESI

    ESIElement::Pointer cachedESITree;
#endif
    int64_t objectLen() const { return mem().object_sz; }
    int64_t contentLen() const { return objectLen() - mem().baseReply().hdr_sz; }

    /// claim shared ownership of this entry (for use in a given context)
    /// matching lock() and unlock() contexts eases leak triage but is optional
    void lock(const char *context);

    /// disclaim shared ownership; may remove entry from store and delete it
    /// returns remaining lock level (zero for unlocked and possibly gone entry)
    int unlock(const char *context);

    /// returns a local concurrent use counter, for debugging
    int locks() const { return static_cast<int>(lock_count); }

    /// update last reference timestamp and related Store metadata
    void touch();

    /// One of the three methods to get rid of an unlocked StoreEntry object.
    /// Removes all unlocked (and marks for eventual removal all locked) Store
    /// entries, including attached and unattached entries that have our key.
    /// Also destroys us if we are unlocked or makes us private otherwise.
    void release(const bool shareable = false);

    /// One of the three methods to get rid of an unlocked StoreEntry object.
    /// May destroy this object if it is unlocked; does nothing otherwise.
    /// Unlike release(), may not trigger eviction of underlying store entries,
    /// but, unlike destroyStoreEntry(), does honor an earlier release request.
    void abandon(const char *context) { if (!locked()) doAbandon(context); }

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
    void append(char const *, int) override;
    void vappendf(const char *, va_list) override;
    void buffer() override;
    void flush() override;

protected:
    typedef Store::EntryGuard EntryGuard;

    void storeWritingCheckpoint();
    /// does nothing except throwing if disk-associated data members are inconsistent
    void checkDisk() const;

private:
    void doAbandon(const char *context);
    bool checkTooBig() const;
    void forcePublicKey(const cache_key *newkey);
    StoreEntry *adjustVary();
    const cache_key *calcPublicKey(const KeyScope keyScope);

    /// flags [truncated or too big] entry with ENTRY_BAD_LENGTH and releases it
    void lengthWentBad(const char *reason);

    static Mem::Allocator *pool;

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
typedef void (*STOREGETCLIENT) (StoreEntry *, void *cbdata);

namespace Store {

/// a smart pointer similar to std::unique_ptr<> that automatically
/// release()s and unlock()s the guarded Entry on stack-unwinding failures
class EntryGuard {
public:
    /// \param entry either nil or a locked Entry to manage
    /// \param context default unlock() message
    EntryGuard(Entry *entry, const char *context):
        entry_(entry), context_(context) {
        assert(!entry_ || entry_->locked());
    }

    ~EntryGuard() {
        if (entry_) {
            // something went wrong -- the caller did not unlockAndReset() us
            onException();
        }
    }

    EntryGuard(EntryGuard &&) = delete; // no copying or moving (for now)

    /// like std::unique_ptr::get()
    /// \returns nil or the guarded (locked) entry
    Entry *get() {
        return entry_;
    }

    /// like std::unique_ptr::reset()
    /// stops guarding the entry
    /// unlocks the entry (which may destroy it)
    void unlockAndReset(const char *resetContext = nullptr) {
        if (entry_) {
            entry_->unlock(resetContext ? resetContext : context_);
            entry_ = nullptr;
        }
    }

private:
    void onException() noexcept;

    Entry *entry_; ///< the guarded Entry or nil
    const char *context_; ///< default unlock() message
};

void Stats(StoreEntry *output);
void Maintain(void *unused);
}; // namespace Store

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
StoreEntry *storeCreatePureEntry(const char *storeId, const char *logUrl, const HttpRequestMethod&);

/// \ingroup StoreAPI
void storeInit(void);

/// \ingroup StoreAPI
void storeConfigure(void);

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

/// One of the three methods to get rid of an unlocked StoreEntry object.
/// This low-level method ignores lock()ing and release() promises. It never
/// leaves the entry in the local store_table.
/// TODO: Hide by moving its functionality into the StoreEntry destructor.
extern FREE destroyStoreEntry;

/// \ingroup StoreAPI
void storeGetMemSpace(int size);

#endif /* SQUID_STORE_H */

