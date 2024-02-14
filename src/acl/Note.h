/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_NOTE_H
#define SQUID_SRC_ACL_NOTE_H

#include "acl/CharacterSetOption.h"
#include "acl/Data.h"
#include "acl/Strategy.h"
#include "Notes.h"

namespace Acl {

/// common parent of several ACLs dealing with transaction annotations
class AnnotationStrategy: public ACLStrategy<NotePairs::Entry *>
{
public:
    AnnotationStrategy(): delimiters(CharacterSet(__FILE__, ",")) {}

    const Acl::Options &options() override;

    Acl::CharacterSetOptionValue delimiters; ///< annotation separators
};

} // namespace Acl

/// \ingroup ACLAPI
class ACLNoteStrategy: public Acl::AnnotationStrategy
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
    bool requiresRequest() const override { return true; }

private:
    bool matchNotes(ACLData<MatchType> *, const NotePairs *) const;
};

#endif /* SQUID_SRC_ACL_NOTE_H */

