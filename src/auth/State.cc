#include "config.h"

#if USE_AUTH
#include "auth/State.h"

CBDATA_GLOBAL_TYPE(authenticateStateData);

void
authenticateStateFree(authenticateStateData * r)
{
    r->auth_user_request = NULL;
    cbdataFree(r);
}
#endif /* USE_AUTH */
