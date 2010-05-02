/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_FD_NOTES_H
#define SQUID_IPC_FD_NOTES_H

namespace Ipc
{

/// We cannot send char* FD notes to other processes. Pass int IDs and convert.

typedef enum { fdnNone, fdnHttpSocket, fdnEnd } FdNoteId; ///< fd_note() label

extern const char *FdNote(int fdNodeId); ///< converts FdNoteId into a string

} // namespace Ipc;


#endif /* SQUID_IPC_FD_NOTES_H */
