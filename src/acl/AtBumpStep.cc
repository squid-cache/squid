#include "squid.h"
#include "acl/Checklist.h"
#include "acl/AtBumpStep.h"
#include "acl/AtBumpStepData.h"
#include "client_side.h"
#include "ssl/ServerBump.h"

int
ACLAtStepStrategy::match (ACLData<Ssl::BumpStep> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    Ssl::ServerBump *bump;
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
