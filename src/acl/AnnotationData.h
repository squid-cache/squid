/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLANNOTATIONDATA_H
#define SQUID_ACLANNOTATIONDATA_H

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
    virtual bool match(NotePairs::Entry *) { return true; }
    virtual SBufList dump() const;
    virtual void parse();
    virtual bool empty() const { return notes->empty(); }
    virtual ACLData<NotePairs::Entry *> *clone() const;

    /// Stores annotations into pairs.
    void annotate(NotePairs::Pointer pairs, const CharacterSet *delimiters, const AccessLogEntry::Pointer &al);

private:
    Notes::Pointer notes;
};

#endif /* SQUID_ACLANNOTATIONDATA_H */

