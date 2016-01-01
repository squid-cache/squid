/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/MyPortName.h"
#include "acl/StringData.h"
#include "anyp/PortCfg.h"
#include "HttpRequest.h"

/* for ConnStateData */
#include "client_side.h"

int
ACLMyPortNameStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    if (checklist->conn() != NULL && checklist->conn()->port != NULL)
        return data->match(checklist->conn()->port->name);
    if (checklist->request != NULL)
        return data->match(checklist->request->myportname.termedBuf());
    return 0;
}

ACLMyPortNameStrategy *
ACLMyPortNameStrategy::Instance()
{
    return &Instance_;
}

ACLMyPortNameStrategy ACLMyPortNameStrategy::Instance_;

