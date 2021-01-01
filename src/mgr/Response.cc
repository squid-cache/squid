/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "CacheManager.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/ActionCreator.h"
#include "mgr/ActionProfile.h"
#include "mgr/Response.h"

Mgr::Response::Response(unsigned int aRequestId, Action::Pointer anAction):
    Ipc::Response(aRequestId), action(anAction)
{
    Must(!action || action->name()); // if there is an action, it must be named
}

Mgr::Response::Response(const Response& response):
    Ipc::Response(response.requestId), action(response.action)
{
}

Mgr::Response::Response(const Ipc::TypedMsgHdr& msg):
    Ipc::Response(0)
{
    msg.checkType(Ipc::mtCacheMgrResponse);
    msg.getPod(requestId);
    Must(requestId != 0);

    if (msg.hasMoreData()) {
        String actionName;
        msg.getString(actionName);
        action = CacheManager::GetInstance()->createNamedAction(actionName.termedBuf());
        Must(hasAction());
        action->unpack(msg);
    }
}

void
Mgr::Response::pack(Ipc::TypedMsgHdr& msg) const
{
    Must(requestId != 0);
    msg.setType(Ipc::mtCacheMgrResponse);
    msg.putPod(requestId);
    if (hasAction()) {
        msg.putString(action->name());
        action->pack(msg);
    }
}

Ipc::Response::Pointer
Mgr::Response::clone() const
{
    return new Response(*this);
}

bool
Mgr::Response::hasAction() const
{
    return action != NULL;
}

const Mgr::Action&
Mgr::Response::getAction() const
{
    Must(hasAction());
    return *action;
}

