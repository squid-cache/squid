/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "Debug.h"
#include "ipc/FdNotes.h"
#include "sbuf/SBuf.h"

const SBuf &
Ipc::FdNote(int fdNoteId)
{
    static const SBuf FdNotes[Ipc::fdnEnd] = {
        SBuf("None"), // fdnNone
        SBuf("HTTP Socket"), // fdnHttpSocket
        SBuf("HTTPS Socket"), // fdnHttpsSocket
        SBuf("FTP Socket"), // fdnFtpSocket
#if SQUID_SNMP
        SBuf("Incoming SNMP Socket"), // fdnInSnmpSocket
        SBuf("Outgoing SNMP Socket"), // fdnOutSnmpSocket
#endif
        SBuf("Incoming ICP Socket"), // fdnInIcpSocket
        SBuf("Incoming HTCP Socket") // fdnInHtcpSocket
    };

    if (fdnNone < fdNoteId && fdNoteId < fdnEnd)
        return FdNotes[fdNoteId];

    debugs(54, DBG_IMPORTANT, HERE << "salvaged bug: wrong fd_note ID: " << fdNoteId);
    return FdNotes[fdnNone];
}

