/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_NOTEDATA_H
#define SQUID_SRC_ACL_NOTEDATA_H

#include "acl/Data.h"
#include "Notes.h"
#include "SquidString.h"

class ACLStringData;

/// \ingroup ACLAPI
class ACLNoteData : public ACLData<NotePairs::Entry *>
{
    MEMPROXY_CLASS(ACLNoteData);

public:
    ACLNoteData();
    ~ACLNoteData() override;
    bool match(NotePairs::Entry *) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override;

private:
    SBuf name;                   ///< Note name to check. It is always set
    ACLStringData *values; ///< if set, at least one value must match
};

#endif /* SQUID_SRC_ACL_NOTEDATA_H */

