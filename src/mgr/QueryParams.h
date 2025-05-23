/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_QUERYPARAMS_H
#define SQUID_SRC_MGR_QUERYPARAMS_H

#include "ipc/forward.h"
#include "mgr/QueryParam.h"
#include "parser/forward.h"
#include "SquidString.h"

#include <utility>
#include <vector>

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
    static void Parse(Parser::Tokenizer &, QueryParams &);

private:
    /// find query parameter by name
    Params::const_iterator find(const String& name) const;
    /// creates a parameter of the specified type
    static QueryParam::Pointer CreateParam(QueryParam::Type aType);

private:
    Params params;
};

} // namespace Mgr

#endif /* SQUID_SRC_MGR_QUERYPARAMS_H */

