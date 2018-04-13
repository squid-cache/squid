/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLCONNMARK_H
#define SQUID_ACLCONNMARK_H

#include "acl/Acl.h"
#include "ip/forward.h"
#include "ip/NfMarkConfig.h"
#include "parser/Tokenizer.h"

#include <vector>

namespace Acl {

class ConnMark : public ACL
{
    MEMPROXY_CLASS(ConnMark);

public:
    /* ACL API */
    virtual char const *typeString() const override;
    virtual void parse() override;
    virtual int match(ACLChecklist *checklist) override;
    virtual SBufList dump() const override;
    virtual bool empty() const override;

private:
    std::vector<Ip::NfMarkConfig> marks; ///< marks/masks in configured order
};

} // namespace Acl

#endif /* SQUID_ACLCONNMARK_H */

