/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_MEMOBJECT_H
#define SQUID_MEMOBJECT_H

#include "CommRead.h"
#include "dlink.h"
#include "http/RequestMethod.h"
#include "RemovalPolicy.h"
#include "sbuf/SBuf.h"
#include "SquidString.h"
#include "stmem.h"
#include "store/forward.h"
#include "StoreIOBuffer.h"
#include "StoreIOState.h"
#include "typedefs.h" //for IRCB

#if USE_DELAY_POOLS
#include "DelayId.h"
#endif

typedef void STMCB (void *data, StoreIOBuffer wroteBuffer);
typedef void STABH(void *);

class store_client;
class HttpRequest;
class HttpReply;

class MemObject
{
    MEMPROXY_CLASS(MemObject);

public:
    static size_t inUseCount();

    void dump() const;
    MemObject();
    ~MemObject();

    /// Sets store ID, log URI, and request method (unless already set). Does
    /// not clobber the method so that, say, a HEAD hit for a GET entry keeps
    /// the GET method that matches the entry key. Same for the other parts of
    /// the trio because the entry filling code may expect them to be constant.
    /// XXX: Avoid this method. We plan to remove it and make the trio constant
    /// after addressing the XXX in MemStore::get().
    void setUris(char const *aStoreId, char const *aLogUri, const HttpRequestMethod &aMethod);

    /// whether setUris() has been called
    bool hasUris() const;

    void write(const StoreIOBuffer &buf);
    void unlinkRequest();
    HttpReply const *getReply() const;
    void replaceHttpReply(HttpReply *newrep);
    void stat (MemBuf * mb) const;
    int64_t endOffset () const;
    void markEndOfReplyHeaders(); ///< sets _reply->hdr_sz to endOffset()
    /// negative if unknown; otherwise, expected object_sz, expected endOffset
    /// maximum, and stored reply headers+body size (all three are the same)
    int64_t expectedReplySize() const;
    int64_t size() const;
    void reset();
    int64_t lowestMemReaderOffset() const;
    bool readAheadPolicyCanRead() const;
    void addClient(store_client *);
    /* XXX belongs in MemObject::swapout, once swaphdrsz is managed
     * better
     */
    int64_t objectBytesOnDisk() const;
    int64_t policyLowestOffsetToKeep(bool swap) const;
    int64_t availableForSwapOut() const; ///< buffered bytes we have not swapped out yet
    void trimSwappable();
    void trimUnSwappable();
    bool isContiguous() const;
    int mostBytesWanted(int max, bool ignoreDelayPools) const;
    void setNoDelay(bool const newValue);
#if USE_DELAY_POOLS
    DelayId mostBytesAllowed() const;
#endif

#if URL_CHECKSUM_DEBUG

    void checkUrlChecksum() const;
#endif

    /// Before StoreID, code assumed that MemObject stores Request URI.
    /// After StoreID, some old code still incorrectly assumes that.
    /// Use this method to mark that incorrect assumption.
    const char *urlXXX() const { return storeId(); }

    /// Entry StoreID (usually just Request URI); if a buggy code requests this
    /// before the information is available, returns an "[unknown_URI]" string.
    const char *storeId() const;

    /// client request URI used for logging; storeId() by default
    const char *logUri() const;

    HttpRequestMethod method;
    mem_hdr data_hdr;
    int64_t inmem_lo = 0;
    dlink_list clients;

    size_t clientCount() const {return nclients;}

    bool clientIsFirst(void *sc) const {return (clients.head && sc == clients.head->data);}

    int nclients = 0;

    class SwapOut
    {
    public:
        int64_t queue_offset = 0; ///< number of bytes sent to SwapDir for writing
        StoreIOState::Pointer sio;

        /// Decision states for StoreEntry::swapoutPossible() and related code.
        typedef enum { swNeedsCheck = 0, swImpossible = -1, swPossible = +1, swStarted } Decision;
        Decision decision = swNeedsCheck; ///< current decision state
    };

    SwapOut swapout;

    /* TODO: Remove this change-minimizing hack */
    using Io = Store::IoStatus;
    static constexpr Io ioUndecided = Store::ioUndecided;
    static constexpr Io ioReading = Store::ioReading;
    static constexpr Io ioWriting = Store::ioWriting;
    static constexpr Io ioDone = Store::ioDone;

    /// State of an entry with regards to the [shared] in-transit table.
    class XitTable
    {
    public:
        int32_t index = -1; ///< entry position inside the in-transit table
        Io io = ioUndecided; ///< current I/O state
    };
    XitTable xitTable; ///< current [shared] memory caching state for the entry

    /// State of an entry with regards to the [shared] memory caching.
    class MemCache
    {
    public:
        int32_t index = -1; ///< entry position inside the memory cache
        int64_t offset = 0; ///< bytes written/read to/from the memory cache so far

        Io io = ioUndecided; ///< current I/O state
    };
    MemCache memCache; ///< current [shared] memory caching state for the entry

    /* Read only - this reply must be preserved by store clients */
    /* The original reply. possibly with updated metadata. */
    HttpRequest *request = nullptr;

    struct timeval start_ping;
    IRCB *ping_reply_callback;
    void *ircb_data = nullptr;

    struct abort_ {
        abort_() { callback = nullptr; }
        STABH *callback;
        void *data = nullptr;
    } abort;
    RemovalPolicyNode repl;
    int id = 0;
    int64_t object_sz = -1;
    size_t swap_hdr_sz = 0;
#if URL_CHECKSUM_DEBUG
    unsigned int chksum = 0;
#endif

    SBuf vary_headers;

    void delayRead(DeferredRead const &);
    void kickReads();

private:
    HttpReply *_reply = nullptr;

    mutable String storeId_; ///< StoreId for our entry (usually request URI)
    mutable String logUri_;  ///< URI used for logging (usually request URI)

    DeferredReadManager deferredReads;
};

/** global current memory removal policy */
extern RemovalPolicy *mem_policy;

#endif /* SQUID_MEMOBJECT_H */

