/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ESISEGMENT_H
#define SQUID_ESISEGMENT_H

/* TODO: Factor the store memory segment management into a reusable code block
 * or perhaps use membuffers here?
 */

#include "base/RefCount.h"
#include "cbdata.h"
#include "defines.h"
#include "SquidString.h"

class ESISegment : public RefCountable
{

public:
    typedef RefCount<ESISegment> Pointer;
    static void ListAppend (Pointer &, char const *, size_t);
    static void ListTransfer (Pointer &from, Pointer &to);
    void *operator new (size_t byteCount);
    void operator delete (void *address);

    ESISegment();
    ESISegment(ESISegment const &);
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

#endif /* SQUID_ESISEGMENT_H */

