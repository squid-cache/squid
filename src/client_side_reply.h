/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CLIENTSIDEREPLY_H
#define SQUID_CLIENTSIDEREPLY_H

#include "acl/forward.h"
#include "client_side_request.h"
#include "ip/forward.h"
#include "RequestFlags.h"
#include "StoreClient.h"

class ErrorState;

/* XXX make static method */

class clientReplyContext : public RefCountable, public StoreClient
{
    CBDATA_CLASS(clientReplyContext);

public:
    static STCB CacheHit;
    static STCB HandleIMSReply;
    static STCB SendMoreData;

    clientReplyContext(ClientHttpRequest *);
    ~clientReplyContext() override;

    void saveState();
    void restoreState();
    void purgeRequest ();
    void doGetMoreData();
    void identifyStoreObject();
    void identifyFoundObject(StoreEntry *entry, const char *detail);
    int storeOKTransferDone() const;
    int storeNotOKTransferDone() const;
    /// replaces current response store entry with the given one
    void setReplyToStoreEntry(StoreEntry *e, const char *reason);
    /// builds error using clientBuildError() and calls setReplyToError() below
    void setReplyToError(err_type, Http::StatusCode, char const *, const ConnStateData *, HttpRequest *, const char *,
#if USE_AUTH
                         Auth::UserRequest::Pointer);
#else
                         void * unused);
#endif
    /// creates a store entry for the reply and appends err to it
    void setReplyToError(const HttpRequestMethod& method, ErrorState *err);
    /// creates a store entry for the reply and appends error reply to it
    void setReplyToReply(HttpReply *reply);
    void createStoreEntry(const HttpRequestMethod& m, RequestFlags flags);
    void removeStoreReference(store_client ** scp, StoreEntry ** ep);
    void removeClientStoreReference(store_client **scp, ClientHttpRequest *http);
    void startError(ErrorState * err);
    void processExpired();
    clientStream_status_t replyStatus();
    void processMiss();
    void traceReply(clientStreamNode * node);
    const char *storeId() const { return (http->store_id.size() > 0 ? http->store_id.termedBuf() : http->uri); }

    Http::StatusCode purgeStatus;

    /* StoreClient API */
    LogTags *loggingTags() const override;

    ClientHttpRequest *http;
    /// Base reply header bytes received from Store.
    /// Compatible with ClientHttpRequest::Out::offset.
    /// Not to be confused with ClientHttpRequest::Out::headers_sz.
    int headers_sz;
    store_client *sc;       /* The store_client we're using */
    size_t reqsize;
    size_t reqofs;

    Store::ReadBuffer storeReadBuffer; ///< XXX

    struct Flags {
        Flags() : storelogiccomplete(0), complete(0), headersSent(false) {}

        unsigned storelogiccomplete:1;
        unsigned complete:1;        ///< we have read all we can from upstream
        bool headersSent;
    } flags;
    clientStreamNode *ourNode;  /* This will go away if/when this file gets refactored some more */

private:
    /* StoreClient API */
    void fillChecklist(ACLFilledChecklist &) const override;

    clientStreamNode *getNextNode() const;
    void makeThisHead();
    bool errorInStream(StoreIOBuffer const &result, size_t const &sizeToProcess)const ;
    void sendStreamError(StoreIOBuffer const &result);
    void pushStreamData(StoreIOBuffer const &result, char *source);
    clientStreamNode * next() const;
    HttpReply *reply;
    void processReplyAccess();
    static ACLCB ProcessReplyAccessResult;
    void processReplyAccessResult(const Acl::Answer &accessAllowed);
    void cloneReply();
    void buildReplyHeader ();
    bool alwaysAllowResponse(Http::StatusCode sline) const;
    int checkTransferDone();
    void processOnlyIfCachedMiss();
    bool processConditional();
    void cacheHit(StoreIOBuffer result);
    void handleIMSReply(StoreIOBuffer result);
    void sendMoreData(StoreIOBuffer result);
    void triggerInitialStoreRead();
    void sendClientOldEntry();
    void purgeAllCached();
    /// attempts to release the cached entry
    /// \returns whether the entry was released
    bool purgeEntry(StoreEntry &, const Http::MethodType, const char *descriptionPrefix = "");
    /// releases both cached GET and HEAD entries
    void purgeDoPurge();
    void forgetHit();
    bool blockedHit() const;
    const char *storeLookupString(bool found) const { return found ? "match" : "mismatch"; }
    void detailStoreLookup(const char *detail);

    void sendBodyTooLargeError();
    void sendPreconditionFailedError();
    void sendNotModified();
    void sendNotModifiedOrPreconditionFailedError();
    void sendClientUpstreamResponse(const StoreIOBuffer &upstreamResponse);

    /// Classification of the initial Store lookup.
    /// This very first lookup happens without the Vary-driven key augmentation.
    /// TODO: Exclude internal Store match bans from the "mismatch" category.
    const char *firstStoreLookup_ = nullptr;

    /* (stale) cache hit information preserved during IMS revalidation */
    StoreEntry *old_entry;
    store_client *old_sc;
    time_t old_lastmod;
    String old_etag;
    size_t old_reqofs;
    size_t old_reqsize;

    bool deleting;

    typedef enum {
        crNone = 0, ///< collapsed revalidation is not allowed for this context
        crInitiator, ///< we initiated collapsed revalidation request
        crSlave ///< we collapsed on the existing revalidation request
    } CollapsedRevalidation;

    CollapsedRevalidation collapsedRevalidation;
};

// TODO: move to SideAgent parent, when we have one
void purgeEntriesByUrl(HttpRequest *, const char *);

#endif /* SQUID_CLIENTSIDEREPLY_H */

