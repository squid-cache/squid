/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "acl/AtStep.h"
#include "acl/AtStepData.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "http/Stream.h"
#if USE_OPENSSL
#include "ssl/ServerBump.h"
#endif

int
ACLAtStepStrategy::match (ACLData<XactionStep> * &data, ACLFilledChecklist *checklist)
{
    #if USE_OPENSSL
    Ssl::ServerBump *bump = NULL;
    if (checklist->conn() != NULL && (bump = checklist->conn()->serverBump()))
        return data->match(bump->step);
    else
        return data->match(xstepTlsBump1);
#endif

    if (data->match(xstepGeneratingConnect)) {
        if (!checklist->request)
            return 0; // we have warned about the missing request earlier

        if (!checklist->request->masterXaction) {
            debugs(28, DBG_IMPORTANT, "missing MasterXaction object, treating as a mismatch");
            return 0;
        }

        return checklist->request->masterXaction->generatingConnect ? 1 : 0;
    }

    return 0;
}
