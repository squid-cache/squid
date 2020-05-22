/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_INT_PARAM_H
#define SQUID_MGR_INT_PARAM_H

#include "ipc/forward.h"
#include "mgr/forward.h"
#include "mgr/QueryParam.h"
#include <vector>

namespace Mgr
{

class IntParam: public QueryParam
{
public:
    IntParam();
    IntParam(const std::vector<int>& anArray);
    virtual void pack(Ipc::TypedMsgHdr& msg) const;
    virtual void unpackValue(const Ipc::TypedMsgHdr& msg);
    const std::vector<int>& value() const;

private:
    std::vector<int> array;
};

} // namespace Mgr

#endif /* SQUID_MGR_INT_PARAM_H */

