/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_QUERYPARAM_H
#define SQUID_SRC_MGR_QUERYPARAM_H

#include "base/RefCount.h"
#include "ipc/forward.h"

namespace Mgr
{

class QueryParam: public RefCountable
{
public:
    typedef enum {ptInt = 1, ptString} Type;
    typedef RefCount<QueryParam> Pointer;

public:
    QueryParam(Type aType): type(aType) {}
    ~QueryParam() override {}
    virtual void pack(Ipc::TypedMsgHdr& msg) const = 0; ///< store parameter into msg
    virtual void unpackValue(const Ipc::TypedMsgHdr& msg) = 0; ///< load parameter value from msg

private:
    QueryParam(const QueryParam&); // not implemented
    QueryParam& operator= (const QueryParam&); // not implemented

public:
    Type type;
};

} // namespace Mgr

#endif /* SQUID_SRC_MGR_QUERYPARAM_H */

