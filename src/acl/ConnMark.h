/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLCONNMARK_H
#define SQUID_ACLCONNMARK_H

#include "acl/Acl.h"
#include "ip/forward.h"
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

    /// a mark/mask pair for matching CONNMARKs
    typedef std::pair<nfmark_t, nfmark_t> ConnMarkQuery;

private:
    nfmark_t getNumber(Parser::Tokenizer &tokenizer, const SBuf &token) const;
    std::vector<ConnMarkQuery> marks; ///< mark/mask pairs in configured order
};

} // namespace Acl

#endif /* SQUID_ACLCONNMARK_H */

