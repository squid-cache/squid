/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_STRING_PARAM_H
#define SQUID_MGR_STRING_PARAM_H

#include "ipc/forward.h"
#include "mgr/forward.h"
#include "mgr/QueryParam.h"
#include "SquidString.h"

namespace Mgr
{

class StringParam: public QueryParam
{
public:
    StringParam();
    StringParam(const String& aString);
    virtual void pack(Ipc::TypedMsgHdr& msg) const;
    virtual void unpackValue(const Ipc::TypedMsgHdr& msg);
    const String& value() const;

private:
    String str;
};

} // namespace Mgr

#endif /* SQUID_MGR_STRING_PARAM_H */

