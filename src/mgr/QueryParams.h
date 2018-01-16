/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_QUERY_PARAMS_H
#define SQUID_MGR_QUERY_PARAMS_H

#include "ipc/forward.h"
#include "mgr/QueryParam.h"
#include "SquidString.h"
#include <vector>
#include <utility>

namespace Mgr
{

class QueryParams
{
public:
    typedef std::pair<String, QueryParam::Pointer> Param;
    typedef std::vector<Param> Params;

public:
    /// returns query parameter by name
    QueryParam::Pointer get(const String& name) const;
    void pack(Ipc::TypedMsgHdr& msg) const; ///< store params into msg
    void unpack(const Ipc::TypedMsgHdr& msg); ///< load params from msg
    /// parses the query string parameters
    static bool Parse(const String& aParamsStr, QueryParams& aParams);

private:
    /// find query parameter by name
    Params::const_iterator find(const String& name) const;
    /// creates a parameter of the specified type
    static QueryParam::Pointer CreateParam(QueryParam::Type aType);
    /// parses string like "param=value"; returns true if success
    static bool ParseParam(const String& paramStr, Param& param);

private:
    Params params;
};

} // namespace Mgr

#endif /* SQUID_MGR_QUERY_PARAMS_H */

