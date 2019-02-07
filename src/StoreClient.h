/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORECLIENT_H
#define SQUID_STORECLIENT_H

#include "dlink.h"
#include "StoreIOBuffer.h"
#include "StoreIOState.h"

typedef void STCB(void *, StoreIOBuffer);   /* store callback */

class StoreEntry;

class StoreClient
{

public:
    virtual ~StoreClient () {}

    virtual void created (StoreEntry *newEntry) = 0;
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
    } _callback;
};

void storeClientCopy(store_client *, StoreEntry *, StoreIOBuffer, STCB *, void *);
store_client* storeClientListAdd(StoreEntry * e, void *data);
int storeClientCopyPending(store_client *, StoreEntry * e, void *data);
int storeUnregister(store_client * sc, StoreEntry * e, void *data);
int storePendingNClients(const StoreEntry * e);
int storeClientIsThisAClient(store_client * sc, void *someClient);

#endif /* SQUID_STORECLIENT_H */

