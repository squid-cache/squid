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
#include "HttpRequestMethod.h"
#include "RemovalPolicy.h"
#include "SBuf.h"
#include "stmem.h"
#include "StoreIOBuffer.h"
#include "StoreIOState.h"

#if USE_DELAY_POOLS
#include "DelayId.h"
#endif

typedef void STMCB (void *data, StoreIOBuffer wroteBuffer);

class store_client;
class HttpRequest;
class HttpReply;

class MemObject
{

public:
    static size_t inUseCount();
    MEMPROXY_CLASS(MemObject);

    void dump() const;
    MemObject();
    ~MemObject();

    /// sets store ID, log URI, and request method; TODO: find a better name
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
    int64_t inmem_lo;
    dlink_list clients;

    /** \todo move into .cc or .cci */
    size_t clientCount() const {return nclients;}

    bool clientIsFirst(void *sc) const {return (clients.head && sc == clients.head->data);}

    int nclients;

    class SwapOut
    {

    public:
        int64_t queue_offset; ///< number of bytes sent to SwapDir for writing
        StoreIOState::Pointer sio;

        /// Decision states for StoreEntry::swapoutPossible() and related code.
        typedef enum { swNeedsCheck = 0, swImpossible = -1, swPossible = +1, swStarted } Decision;
        Decision decision; ///< current decision state
    };

    SwapOut swapout;

    /// cache "I/O" direction and status
    typedef enum { ioUndecided, ioWriting, ioReading, ioDone } Io;

    /// State of an entry with regards to the [shared] in-transit table.
    class XitTable
    {
    public:
        XitTable(): index(-1), io(ioUndecided) {}

        int32_t index; ///< entry position inside the in-transit table
        Io io; ///< current I/O state
    };
    XitTable xitTable; ///< current [shared] memory caching state for the entry

    /// State of an entry with regards to the [shared] memory caching.
    class MemCache
    {
    public:
        MemCache(): index(-1), offset(0), io(ioUndecided) {}

        int32_t index; ///< entry position inside the memory cache
        int64_t offset; ///< bytes written/read to/from the memory cache so far

        Io io; ///< current I/O state
    };
    MemCache memCache; ///< current [shared] memory caching state for the entry

    bool smpCollapsed; ///< whether this entry gets data from another worker

    /* Read only - this reply must be preserved by store clients */
    /* The original reply. possibly with updated metadata. */
    HttpRequest *request;

    struct timeval start_ping;
    IRCB *ping_reply_callback;
    void *ircb_data;

    struct {
        STABH *callback;
        void *data;
    } abort;
    RemovalPolicyNode repl;
    int id;
    int64_t object_sz;
    size_t swap_hdr_sz;
#if URL_CHECKSUM_DEBUG

    unsigned int chksum;
#endif

    SBuf vary_headers;

    void delayRead(DeferredRead const &);
    void kickReads();

private:
    HttpReply *_reply;

    mutable String storeId_; ///< StoreId for our entry (usually request URI)
    mutable String logUri_;  ///< URI used for logging (usually request URI)

    DeferredReadManager deferredReads;
};

MEMPROXY_CLASS_INLINE(MemObject);

/** global current memory removal policy */
extern RemovalPolicy *mem_policy;

#endif /* SQUID_MEMOBJECT_H */

