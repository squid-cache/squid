/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "comm/Connection.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "ipc/FdNotes.h"
#include "mgr/StoreToCommWriter.h"
#include "Store.h"
#include "StoreClient.h"

CBDATA_NAMESPACED_CLASS_INIT(Mgr, StoreToCommWriter);

Mgr::StoreToCommWriter::StoreToCommWriter(const Comm::ConnectionPointer &conn, StoreEntry* anEntry):
    AsyncJob("Mgr::StoreToCommWriter"),
    clientConnection(conn), entry(anEntry), sc(NULL), writeOffset(0), closer(NULL)
{
    debugs(16, 6, HERE << clientConnection);
    closer = asyncCall(16, 5, "Mgr::StoreToCommWriter::noteCommClosed",
                       CommCbMemFunT<StoreToCommWriter, CommCloseCbParams>(this, &StoreToCommWriter::noteCommClosed));
    comm_add_close_handler(clientConnection->fd, closer);
}

Mgr::StoreToCommWriter::~StoreToCommWriter()
{
    debugs(16, 6, HERE);
    assert(!entry);
    assert(!sc);
    close();
}

/// closes our copy of the client HTTP connection socket
void
Mgr::StoreToCommWriter::close()
{
    if (Comm::IsConnOpen(clientConnection)) {
        if (closer != NULL) {
            comm_remove_close_handler(clientConnection->fd, closer);
            closer = NULL;
        }
        clientConnection->close();
    }
}

void
Mgr::StoreToCommWriter::start()
{
    debugs(16, 6, HERE);
    Must(Comm::IsConnOpen(clientConnection));
    Must(entry != NULL);
    entry->registerAbort(&StoreToCommWriter::Abort, this);
    sc = storeClientListAdd(entry, this);
    Must(sc != NULL);

    // initiate the receive-from-store, write-to-comm sequence
    scheduleStoreCopy();
}

void
Mgr::StoreToCommWriter::scheduleStoreCopy()
{
    debugs(16, 6, HERE);
    Must(entry != NULL);
    Must(sc != NULL);
    StoreIOBuffer readBuf(sizeof(buffer), writeOffset, buffer);
    storeClientCopy(sc, entry, readBuf, &NoteStoreCopied, this);
}

void
Mgr::StoreToCommWriter::NoteStoreCopied(void* data, StoreIOBuffer ioBuf)
{
    Must(data != NULL);
    // make sync Store call async to get async call protections and features
    StoreToCommWriter* writer = static_cast<StoreToCommWriter*>(data);
    typedef UnaryMemFunT<StoreToCommWriter, StoreIOBuffer> MyDialer;
    AsyncCall::Pointer call =
        asyncCall(16, 5, "Mgr::StoreToCommWriter::noteStoreCopied",
                  MyDialer(writer, &StoreToCommWriter::noteStoreCopied, ioBuf));
    ScheduleCallHere(call);
}

void
Mgr::StoreToCommWriter::noteStoreCopied(StoreIOBuffer ioBuf)
{
    debugs(16, 6, HERE);
    Must(!ioBuf.flags.error);
    if (ioBuf.length > 0)
        scheduleCommWrite(ioBuf); // write received action results to client
    else
        Must(doneAll()); // otherwise, why would Store call us with no data?
}

void
Mgr::StoreToCommWriter::scheduleCommWrite(const StoreIOBuffer& ioBuf)
{
    debugs(16, 6, HERE);
    Must(Comm::IsConnOpen(clientConnection));
    Must(ioBuf.data != NULL);
    // write filled buffer
    typedef CommCbMemFunT<StoreToCommWriter, CommIoCbParams> MyDialer;
    AsyncCall::Pointer writer =
        asyncCall(16, 5, "Mgr::StoreToCommWriter::noteCommWrote",
                  MyDialer(this, &StoreToCommWriter::noteCommWrote));
    Comm::Write(clientConnection, ioBuf.data, ioBuf.length, writer, NULL);
}

void
Mgr::StoreToCommWriter::noteCommWrote(const CommIoCbParams& params)
{
    debugs(16, 6, HERE);
    Must(params.flag == Comm::OK);
    Must(clientConnection != NULL && params.fd == clientConnection->fd);
    Must(params.size != 0);
    writeOffset += params.size;
    if (!doneAll())
        scheduleStoreCopy(); // retrieve the next data portion
}

void
Mgr::StoreToCommWriter::noteCommClosed(const CommCloseCbParams &)
{
    debugs(16, 6, HERE);
    Must(!Comm::IsConnOpen(clientConnection));
    mustStop("commClosed");
}

void
Mgr::StoreToCommWriter::swanSong()
{
    debugs(16, 6, HERE);
    if (entry != NULL) {
        if (sc != NULL) {
            storeUnregister(sc, entry, this);
            sc = NULL;
        }
        entry->unregisterAbort();
        entry->unlock("Mgr::StoreToCommWriter::swanSong");
        entry = NULL;
    }
    close();
}

bool
Mgr::StoreToCommWriter::doneAll() const
{
    return entry &&
           entry->store_status == STORE_OK && // the action is over
           writeOffset >= entry->objectLen(); // we wrote all the results
}

void
Mgr::StoreToCommWriter::Abort(void* param)
{
    StoreToCommWriter* mgrWriter = static_cast<StoreToCommWriter*>(param);
    if (Comm::IsConnOpen(mgrWriter->clientConnection))
        mgrWriter->clientConnection->close();
}

