/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
#include "http/forward.h"
#include "mgr/Action.h"
#include "StoreIOBuffer.h"
#include "StoreClient.h" /* XXX: For Store::ReadBuffer */

class CommIoCbParams;
class CommCloseCbParams;

namespace Mgr
{

/// manages receive-from-store, write-to-comm, receive-... sequence
/// for the given StoreEntry and client FD
class StoreToCommWriter: public AsyncJob
{
    CBDATA_INTERMEDIATE();

public:
    StoreToCommWriter(const Comm::ConnectionPointer &conn, StoreEntry *anEntry);
    ~StoreToCommWriter() override;

protected:
    /* AsyncJob API */
    void start() override;
    void swanSong() override;
    bool doneAll() const override;

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

    // Unlike most STCB buffers that see HTTP response headers before the body,
    // some StoreToCommWriter instances may never see HTTP response headers in
    // this buffer because each SMP kid-specific/non-aggregating cache manager
    // action response contains just raw cache manager report body fragments.
    // However, since some instances do see HTTP headers, we use HTTP-focused
    // Store::ReadBuffer here even though StoreToCommWriter does not speak HTTP.
    Store::ReadBuffer buffer; ///< action results; Store fills, Comm writes
};

} // namespace Mgr

#endif /* SQUID_MGR_STORE_TO_COMM_WRITER_H */

