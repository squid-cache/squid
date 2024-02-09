/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ESI_SEGMENT_H
#define SQUID_SRC_ESI_SEGMENT_H

/* TODO: Factor the store memory segment management into a reusable code block
 * or perhaps use membuffers here?
 */

#include "base/RefCount.h"
#include "cbdata.h"
#include "http/forward.h"
#include "SquidString.h"

class ESISegment : public RefCountable
{
    CBDATA_CLASS(ESISegment);

public:
    typedef RefCount<ESISegment> Pointer;
    static void ListAppend (Pointer &, char const *, size_t);
    static void ListTransfer (Pointer &from, Pointer &to);

    ESISegment() : len(0), next(nullptr) {*buf = 0;}
    ESISegment(ESISegment const &);
    ~ESISegment() override {}

    ESISegment::Pointer cloneList() const;
    char *listToChar() const;
    void listAppend (char const *s, size_t length);
    void adsorbList (ESISegment::Pointer from);
    size_t space() const;

    char buf[HTTP_REQBUF_SZ];
    size_t len; /* how much data has been pushed into this */
    Pointer next;
    size_t append(char const *, size_t);
    size_t append (Pointer);
    ESISegment const *tail() const;
    ESISegment *tail();
    void dumpToLog() const;

private:
    size_t listLength()const;
    void dumpOne() const;
};

void ESISegmentFreeList (ESISegment::Pointer &head);

#endif /* SQUID_SRC_ESI_SEGMENT_H */

