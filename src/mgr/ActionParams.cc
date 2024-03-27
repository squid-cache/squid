/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    SBuf method;
    msg.getString(method);
    httpMethod = HttpRequestMethod(method);

    SBuf uri;
    msg.getString(uri);
    httpUri.parse(httpMethod, uri);

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
    msg.putString(httpMethod.image());
    // XXX: TypedMsgHdr::maxSize < 8KB URL required minimum capacity
    msg.putString(httpUri.absolute());
    msg.putPod(httpFlags);
    msg.putString(httpOrigin);

    msg.putString(actionName);
    msg.putString(userName);
    msg.putString(password);
    queryParams.pack(msg);
}

