/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#include "squid.h"
#include "CacheManager.h"
#include "mgr/Registration.h"

void
Mgr::RegisterAction(char const * action, char const * desc,
                    OBJH * handler,
                    int pw_req_flag, int atomic)
{
    CacheManager::GetInstance()->registerProfile(action, desc, handler,
            pw_req_flag, atomic);
}

void
Mgr::RegisterAction(char const * action, char const * desc,
                    ClassActionCreationHandler *handler,
                    int pw_req_flag, int atomic)
{
    CacheManager::GetInstance()->registerProfile(action, desc, handler,
            pw_req_flag, atomic);
}
