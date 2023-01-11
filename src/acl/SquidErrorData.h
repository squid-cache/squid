/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSQUIDERRORDATA_H
#define SQUID_ACLSQUIDERRORDATA_H

#include "acl/Data.h"
#include "base/CbDataList.h"
#include "error/forward.h"

/// \ingroup ACLAPI
class ACLSquidErrorData : public ACLData<err_type>
{

public:
    ACLSquidErrorData(): ACLData<err_type>() {};

    virtual ~ACLSquidErrorData() {}
    virtual bool match(err_type err);
    virtual SBufList dump() const;
    virtual void parse();
    virtual bool empty() const;
    virtual ACLData<err_type> *clone() const;

private:
    CbDataListContainer <err_type> errors;
};

#endif //SQUID_ACLSQUIDERRORDATA_H

