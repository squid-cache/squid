/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_FD_NOTES_H
#define SQUID_IPC_FD_NOTES_H

namespace Ipc
{

/// We cannot send char* FD notes to other processes. Pass int IDs and convert.

/// fd_note() label ID
typedef enum { fdnNone, fdnHttpSocket, fdnHttpsSocket,
#if SQUID_SNMP
               fdnInSnmpSocket, fdnOutSnmpSocket,
#endif
               fdnInIcpSocket, fdnInHtcpSocket, fdnEnd
             } FdNoteId;

const char *FdNote(int fdNodeId); ///< converts FdNoteId into a string

} // namespace Ipc;

#endif /* SQUID_IPC_FD_NOTES_H */
