/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORECLIENT_H
#define SQUID_STORECLIENT_H

#include "base/forward.h"
#include "dlink.h"
#include "StoreIOBuffer.h"
#include "StoreIOState.h"

typedef void STCB(void *, StoreIOBuffer);   /* store callback */

class StoreEntry;
class ACLFilledChecklist;
class LogTags;

/// A StoreEntry::getPublic*() caller.
class StoreClient
{

public:
    virtual ~StoreClient () {}

    // TODO: Remove? Probably added to make lookups asynchronous, but they are
    // still blocking. A lot more is needed to support async callbacks.
    /// Handle a StoreEntry::getPublic*() result.
    /// A nil entry indicates a cache miss.
    virtual void created(StoreEntry *) = 0;

    /// \return LogTags (if the class logs transactions) or nil (otherwise)
    virtual LogTags *loggingTags() = 0;

protected:
    /// configure the ACL checklist with the current transaction state
    virtual void fillChecklist(ACLFilledChecklist &) const = 0;

    /// \returns whether the caller must collapse on the given entry
    /// Before returning true, updates common collapsing-related stats.
    /// See also: StoreEntry::hittingRequiresCollapsing().
    bool startCollapsingOn(const StoreEntry &, const bool doingRevalidation);

    // These methods only interpret Squid configuration. Their allowances are
    // provisional -- other factors may prevent collapsed forwarding. The first
    // two exist primarily to distinguish two major CF cases in callers code.
    /// whether Squid configuration allows us to become a CF initiator
    bool mayInitiateCollapsing() const { return onCollapsingPath(); }
    /// whether Squid configuration allows collapsing for this transaction
    bool onCollapsingPath() const;
};

#if USE_DELAY_POOLS
#include "DelayId.h"
#endif

/* keep track each client receiving data from that particular StoreEntry */

class store_client
{
    CBDATA_CLASS(store_client);

public:
    store_client(StoreEntry *);
    ~store_client();
    bool memReaderHasLowerOffset(int64_t) const;
    int getType() const;
    void fail();
    void callback(ssize_t len, bool error = false);
    void doCopy (StoreEntry *e);
    void readHeader(const char *buf, ssize_t len);
    void readBody(const char *buf, ssize_t len);
    void copy(StoreEntry *, StoreIOBuffer, STCB *, void *);
    void dumpStats(MemBuf * output, int clientNumber) const;

    int64_t cmp_offset;
#if STORE_CLIENT_LIST_DEBUG

    void *owner;
#endif

    StoreEntry *entry;      /* ptr to the parent StoreEntry, argh! */
    StoreIOState::Pointer swapin_sio;

    struct {
        bool disk_io_pending;
        bool store_copying;
        bool copy_event_pending;
    } flags;

#if USE_DELAY_POOLS
    DelayId delayId;
    void setDelayId(DelayId delay_id);
#endif

    dlink_node node;
    /* Below here is private - do no alter outside storeClient calls */
    StoreIOBuffer copyInto;

private:
    bool moreToSend() const;

    void fileRead();
    void scheduleDiskRead();
    void scheduleMemRead();
    void scheduleRead();
    bool startSwapin();
    bool unpackHeader(char const *buf, ssize_t len);

    int type;
    bool object_ok;

    /* Until we finish stuffing code into store_client */

public:

    struct Callback {
        Callback ():callback_handler(NULL), callback_data(NULL) {}

        Callback (STCB *, void *);
        bool pending() const;
        STCB *callback_handler;
        void *callback_data;
        CodeContextPointer codeContext; ///< Store client context
    } _callback;
};

void storeClientCopy(store_client *, StoreEntry *, StoreIOBuffer, STCB *, void *);
store_client* storeClientListAdd(StoreEntry * e, void *data);
int storeClientCopyPending(store_client *, StoreEntry * e, void *data);
int storeUnregister(store_client * sc, StoreEntry * e, void *data);
int storePendingNClients(const StoreEntry * e);
int storeClientIsThisAClient(store_client * sc, void *someClient);

#endif /* SQUID_STORECLIENT_H */

