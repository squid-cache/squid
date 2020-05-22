/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Data.h"
#include "acl/SquidErrorData.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "err_type.h"
#include "fatal.h"
#include "wordlist.h"

bool
ACLSquidErrorData::match(err_type err)
{
    CbDataListIterator<err_type> iter(errors);
    while (!iter.end()) {
        err_type localErr = iter.next();
        debugs(28, 4, "check (" << err << "):"  << errorTypeName(err) << " against " <<  errorTypeName(localErr));
        if (err == localErr)
            return true;
    }

    return false;
}

SBufList
ACLSquidErrorData::dump() const
{
    SBufList sl;
    CbDataListIterator<err_type> iter(errors);
    while (!iter.end()) {
        err_type err = iter.next();
        const char *errName = errorTypeName(err);
        sl.push_back(SBuf(errName));
    }

    return sl;
}

void
ACLSquidErrorData::parse()
{
    while (char *token = ConfigParser::NextToken()) {
        err_type err = errorTypeByName(token);

        if (err < ERR_MAX)
            errors.push_back(err);
        else {
            debugs(28, DBG_CRITICAL, "FATAL: Invalid squid error name");
            if (!opt_parse_cfg_only)
                self_destruct();
        }
    }
}

bool
ACLSquidErrorData::empty() const
{
    return errors.empty();
}

ACLData<err_type> *
ACLSquidErrorData::clone() const
{
    if (!errors.empty())
        fatal("ACLSquidError::clone: attempt to clone used ACL");

    return new ACLSquidErrorData (*this);
}

