/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/AsyncCbdataCalls.h"
#include "base/TextException.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "ipc/FdNotes.h"
#include "mgr/StoreToCommWriter.h"
#include "Store.h"
#include "StoreClient.h"

Mgr::StoreToCommWriter::StoreToCommWriter(const Comm::ConnectionPointer &conn, StoreEntry* anEntry):
    AsyncJob("Mgr::StoreToCommWriter"),
    clientConnection(conn), entry(anEntry), sc(nullptr), writeOffset(0), closer(nullptr)
{
    debugs(16, 6, clientConnection);
    closer = asyncCall(16, 5, "Mgr::StoreToCommWriter::noteCommClosed",
                       CommCbMemFunT<StoreToCommWriter, CommCloseCbParams>(this, &StoreToCommWriter::noteCommClosed));
    comm_add_close_handler(clientConnection->fd, closer);
}

Mgr::StoreToCommWriter::~StoreToCommWriter()
{
    debugs(16, 6, MYNAME);
    assert(!entry);
    assert(!sc);
    close();
}

/// closes our copy of the client HTTP connection socket
void
Mgr::StoreToCommWriter::close()
{
    if (Comm::IsConnOpen(clientConnection)) {
        if (closer != nullptr) {
            comm_remove_close_handler(clientConnection->fd, closer);
            closer = nullptr;
        }
        clientConnection->close();
    }
}

void
Mgr::StoreToCommWriter::start()
{
    debugs(16, 6, MYNAME);
    Must(Comm::IsConnOpen(clientConnection));
    Must(entry != nullptr);
    AsyncCall::Pointer call = asyncCall(16, 4, "StoreToCommWriter::Abort", cbdataDialer(&StoreToCommWriter::HandleStoreAbort, this));
    entry->registerAbortCallback(call);
    sc = storeClientListAdd(entry, this);
    Must(sc != nullptr);

    // initiate the receive-from-store, write-to-comm sequence
    scheduleStoreCopy();
}

void
Mgr::StoreToCommWriter::scheduleStoreCopy()
{
    debugs(16, 6, MYNAME);
    Must(entry != nullptr);
    Must(sc != nullptr);
    StoreIOBuffer readBuf(sizeof(buffer), writeOffset, buffer);
    storeClientCopy(sc, entry, readBuf, &NoteStoreCopied, this);
}

void
Mgr::StoreToCommWriter::NoteStoreCopied(void* data, StoreIOBuffer ioBuf)
{
    Must(data != nullptr);
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
    debugs(16, 6, MYNAME);
    Must(!ioBuf.flags.error);
    if (ioBuf.length > 0)
        scheduleCommWrite(ioBuf); // write received action results to client
    else
        Must(doneAll()); // otherwise, why would Store call us with no data?
}

void
Mgr::StoreToCommWriter::scheduleCommWrite(const StoreIOBuffer& ioBuf)
{
    debugs(16, 6, MYNAME);
    Must(Comm::IsConnOpen(clientConnection));
    Must(ioBuf.data != nullptr);
    // write filled buffer
    typedef CommCbMemFunT<StoreToCommWriter, CommIoCbParams> MyDialer;
    AsyncCall::Pointer writer =
        asyncCall(16, 5, "Mgr::StoreToCommWriter::noteCommWrote",
                  MyDialer(this, &StoreToCommWriter::noteCommWrote));
    Comm::Write(clientConnection, ioBuf.data, ioBuf.length, writer, nullptr);
}

void
Mgr::StoreToCommWriter::noteCommWrote(const CommIoCbParams& params)
{
    debugs(16, 6, MYNAME);
    Must(params.flag == Comm::OK);
    Must(clientConnection != nullptr && params.fd == clientConnection->fd);
    Must(params.size != 0);
    writeOffset += params.size;
    if (!doneAll())
        scheduleStoreCopy(); // retrieve the next data portion
}

void
Mgr::StoreToCommWriter::noteCommClosed(const CommCloseCbParams &)
{
    debugs(16, 6, MYNAME);
    if (clientConnection) {
        clientConnection->noteClosure();
        clientConnection = nullptr;
    }
    closer = nullptr;
    mustStop("commClosed");
}

void
Mgr::StoreToCommWriter::swanSong()
{
    debugs(16, 6, MYNAME);
    if (entry != nullptr) {
        if (sc != nullptr) {
            storeUnregister(sc, entry, this);
            sc = nullptr;
        }
        entry->unregisterAbortCallback("StoreToCommWriter done");
        entry->unlock("Mgr::StoreToCommWriter::swanSong");
        entry = nullptr;
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
Mgr::StoreToCommWriter::HandleStoreAbort(StoreToCommWriter *mgrWriter)
{
    if (Comm::IsConnOpen(mgrWriter->clientConnection))
        mgrWriter->clientConnection->close();
}

