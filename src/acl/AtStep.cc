#include "squid.h"

#if USE_OPENSSL

#include "acl/Checklist.h"
#include "acl/AtStep.h"
#include "acl/AtStepData.h"
#include "client_side.h"
#include "ssl/ServerBump.h"

int
ACLAtStepStrategy::match (ACLData<Ssl::BumpStep> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    Ssl::ServerBump *bump = NULL;
    if (checklist->conn() != NULL && (bump = checklist->conn()->serverBump()))
        return data->match(bump->step);
    else
        return data->match(Ssl::bumpStep1);
    return 0;
}

ACLAtStepStrategy *
ACLAtStepStrategy::Instance()
{
    return &Instance_;
}

ACLAtStepStrategy ACLAtStepStrategy::Instance_;

#endif /* USE_OPENSSL */
