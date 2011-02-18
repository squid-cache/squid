#ifndef _SQUID_SRC_COMM_LOOPS_H
#define _SQUID_SRC_COMM_LOOPS_H

#include "comm_err_t.h"

/* Comm layer select loops API.
 *
 * These API functions must be implemented by all FD IO loops used by Squid.
 * Defines are provided short-term for legacy code. These will disappear soon.
 */

namespace Comm
{

/// Initialize the module on Squid startup
extern void SelectLoopInit(void);

/// Mark an FD to be watched for its IO status.
extern void SetSelect(int, unsigned int, PF *, void *, time_t);

/// reset/undo/unregister the watch for an FD which was set by Comm::SetSelect()
extern void ResetSelect(int);

/** Perform a select() or equivalent call.
 * This is used by the main select loop engine to check for FD with IO available.
 */
extern comm_err_t DoSelect(int);

extern void QuickPollRequired(void);

} // namespace Comm

#endif /* _SQUID_SRC_COMM_LOOPS_H */
