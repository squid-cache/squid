/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_INTPARAM_H
#define SQUID_SRC_MGR_INTPARAM_H

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
    void pack(Ipc::TypedMsgHdr& msg) const override;
    void unpackValue(const Ipc::TypedMsgHdr& msg) override;
    const std::vector<int>& value() const;

private:
    std::vector<int> array;
};

} // namespace Mgr

#endif /* SQUID_SRC_MGR_INTPARAM_H */

