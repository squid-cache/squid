#include "config.h"
#include "auth/State.h"

CBDATA_GLOBAL_TYPE(authenticateStateData);

void
authenticateStateFree(authenticateStateData * r)
{
    r->auth_user_request = NULL;
    cbdataFree(r);
}
