/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/MyPortName.h"
#include "acl/StringData.h"
#include "anyp/PortCfg.h"
#include "client_side.h"
#include "http/Stream.h"
#include "HttpRequest.h"

int
ACLMyPortNameStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    if (checklist->conn() != NULL && checklist->conn()->port != NULL)
        return data->match(checklist->conn()->port->name);
    if (checklist->request != NULL)
        return data->match(checklist->request->myportname.termedBuf());
    return 0;
}

