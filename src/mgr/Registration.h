/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_REGISTRATION_H
#define SQUID_MGR_REGISTRATION_H

#include "mgr/forward.h"
#include "typedefs.h"   /* for OBJH */

namespace Mgr
{

void RegisterAction(char const * action, char const * desc,
                    OBJH * handler,
                    int pw_req_flag, int atomic);

void RegisterAction(char const * action, char const * desc,
                    ClassActionCreationHandler *handler,
                    int pw_req_flag, int atomic);

} // namespace Mgr

#endif /* SQUID_MGR_REGISTRATION_H */
