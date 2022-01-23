/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_STORE_TO_COMM_WRITER_H
#define SQUID_MGR_STORE_TO_COMM_WRITER_H

#include "base/AsyncJob.h"
#include "comm/forward.h"
#include "mgr/Action.h"
#include "StoreIOBuffer.h"

class store_client;
class CommIoCbParams;
class CommCloseCbParams;

namespace Mgr
{

/// manages receive-from-store, write-to-comm, receive-... sequence
/// for the given StoreEntry and client FD
class StoreToCommWriter: public AsyncJob
{
    CBDATA_CLASS(StoreToCommWriter);

public:
    StoreToCommWriter(const Comm::ConnectionPointer &conn, StoreEntry *anEntry);
    virtual ~StoreToCommWriter();

protected:
    /* AsyncJob API */
    virtual void start();
    virtual void swanSong();
    virtual bool doneAll() const;

    /// request more action results from the store
    void scheduleStoreCopy();
    /// receive some action results from the store
    void noteStoreCopied(StoreIOBuffer ioBuf);
    static void NoteStoreCopied(void* data, StoreIOBuffer ioBuf);
    /// called by Store if the entry is no longer usable
    static void HandleStoreAbort(StoreToCommWriter *param);

    /// tell Comm to write action results
    void scheduleCommWrite(const StoreIOBuffer& ioBuf);
    /// called by Comm after the action results are written
    void noteCommWrote(const CommIoCbParams& params);
    /// called by Comm if the client socket got closed
    void noteCommClosed(const CommCloseCbParams& params);

    /// closes the local connection to the HTTP client, if any
    void close();

protected:
    Comm::ConnectionPointer clientConnection; ///< HTTP client descriptor

    StoreEntry* entry; ///< store entry with the cache manager response
    store_client* sc; ///< our registration with the store
    int64_t writeOffset; ///< number of bytes written to the client

    AsyncCall::Pointer closer; ///< comm_close handler
    char buffer[HTTP_REQBUF_SZ]; ///< action results; Store fills, Comm writes
};

} // namespace Mgr

#endif /* SQUID_MGR_STORE_TO_COMM_WRITER_H */

