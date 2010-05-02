/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "Debug.h"
#include "ipc/FdNotes.h"


const char *
Ipc::FdNote(int fdNoteId)
{
    static const char *FdNotes[Ipc::fdnEnd] = {
        "None", // fdnNone
        "HTTP Socket" // fdnHttpSocket
    };

    if (fdnNone < fdNoteId && fdNoteId < fdnEnd)
        return FdNotes[fdNoteId];

    debugs(54, 1, HERE << "salvaged bug: wrong fd_note ID: " << fdNoteId);
    return FdNotes[fdnNone];
}
