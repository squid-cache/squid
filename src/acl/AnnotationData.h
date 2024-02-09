/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ANNOTATIONDATA_H
#define SQUID_SRC_ACL_ANNOTATIONDATA_H

#include "AccessLogEntry.h"
#include "acl/Data.h"
#include "Notes.h"

/// \ingroup ACLAPI
class ACLAnnotationData : public ACLData<NotePairs::Entry *>
{
    MEMPROXY_CLASS(ACLAnnotationData);

public:
    ACLAnnotationData();

    /* ACLData<M> API */
    bool match(NotePairs::Entry *) override { return true; }
    SBufList dump() const override;
    void parse() override;
    bool empty() const override { return notes->empty(); }

    /// Stores annotations into pairs.
    void annotate(NotePairs::Pointer pairs, const CharacterSet *delimiters, const AccessLogEntry::Pointer &al);

private:
    Notes::Pointer notes;
};

#endif /* SQUID_SRC_ACL_ANNOTATIONDATA_H */

