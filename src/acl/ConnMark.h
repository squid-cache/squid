/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_CONNMARK_H
#define SQUID_SRC_ACL_CONNMARK_H

#include "acl/Node.h"
#include "ip/forward.h"
#include "ip/NfMarkConfig.h"
#include "parser/Tokenizer.h"

#include <vector>

namespace Acl {

class ConnMark : public Acl::Node
{
    MEMPROXY_CLASS(ConnMark);

public:
    /* Acl::Node API */
    char const *typeString() const override;
    void parse() override;
    int match(ACLChecklist *checklist) override;
    SBufList dump() const override;
    bool empty() const override;

private:
    std::vector<Ip::NfMarkConfig> marks; ///< marks/masks in configured order
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_CONNMARK_H */

