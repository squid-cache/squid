/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLNOTE_H
#define SQUID_ACLNOTE_H

#include "acl/CharacterSetOption.h"
#include "acl/Data.h"
#include "acl/ParameterizedNode.h"
#include "Notes.h"

namespace Acl {

/// common parent of several ACLs dealing with transaction annotations
class AnnotationCheck: public ParameterizedNode< ACLData<NotePairs::Entry *> >
{
public:
    AnnotationCheck(): delimiters(CharacterSet(__FILE__, ",")) {}

    const Acl::Options &options() override;

    Acl::CharacterSetOptionValue delimiters; ///< annotation separators
};

/// a "note" ACL
class NoteCheck: public Acl::AnnotationCheck
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
    bool requiresRequest() const override { return true; }

private:
    bool matchNotes(const NotePairs *) const;
};

} // namespace Acl

#endif /* SQUID_ACLNOTE_H */

