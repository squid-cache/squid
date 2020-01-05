/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/StringParam.h"

Mgr::StringParam::StringParam():
    QueryParam(QueryParam::ptString), str()
{
}

Mgr::StringParam::StringParam(const String& aString):
    QueryParam(QueryParam::ptString), str(aString)
{
}

void
Mgr::StringParam::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.putPod(type);
    msg.putString(str);
}

void
Mgr::StringParam::unpackValue(const Ipc::TypedMsgHdr& msg)
{
    msg.getString(str);
}

const String&
Mgr::StringParam::value() const
{
    return str;
}

