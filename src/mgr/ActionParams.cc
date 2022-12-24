/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/ActionParams.h"
#include "sbuf/StringConvert.h"

Mgr::ActionParams::ActionParams(): httpMethod(Http::METHOD_NONE)
{
}

Mgr::ActionParams::ActionParams(const Ipc::TypedMsgHdr &msg)
{
    msg.getString(httpUri);

    String method;
    msg.getString(method);
    httpMethod.HttpRequestMethodXXX(method.termedBuf());

    msg.getPod(httpFlags);
    msg.getString(httpOrigin);

    msg.getString(actionName);
    msg.getString(userName);
    msg.getString(password);
    queryParams.unpack(msg);
}

void
Mgr::ActionParams::pack(Ipc::TypedMsgHdr &msg) const
{
    msg.putString(httpUri);
    auto foo = SBufToString(httpMethod.image());
    msg.putString(foo);
    msg.putPod(httpFlags);
    msg.putString(httpOrigin);

    msg.putString(actionName);
    msg.putString(userName);
    msg.putString(password);
    queryParams.pack(msg);
}

