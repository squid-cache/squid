/*
 * $Id: ESISequence.h,v 1.4 2004/08/30 05:12:31 robertc Exp $
 *
 * DEBUG: section 86    ESI processing
 * AUTHOR: Robert Collins
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_ESISEQUENCE_H
#define SQUID_ESISEQUENCE_H

#include "squid.h"
#include "ESIElement.h"
#include "ElementList.h"

/* esiSequence */

class esiSequence : public ESIElement
{

public:
    MEMPROXY_CLASS(esiSequence);

    esiSequence(esiTreeParentPtr, bool = false);
    ~esiSequence();

    void render(ESISegment::Pointer);
    bool addElement (ESIElement::Pointer);
    esiProcessResult_t process (int dovars);
    void provideData (ESISegment::Pointer, ESIElement*);
    bool mayFail () const;
    void wontFail();
    void fail(ESIElement *, char const *anError = NULL);
    void makeCachableElements(esiSequence const &old);
    Pointer makeCacheable() const;
    void makeUsableElements(esiSequence const &old, ESIVarState &);
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const;

    ElementList elements; /* unprocessed or rendered nodes */
    size_t processedcount;

    struct
    {

int dovars:
        1; /* for esiVar */
    }

    flags;
    void finish();

protected:
    esiSequence(esiSequence const &);
    esiTreeParentPtr parent;

private:
    int elementIndex (ESIElement::Pointer anElement) const;
    bool mayFail_;
    bool failed;
    esiProcessResult_t processOne(int, size_t);
    bool const provideIncrementalData;
    bool processing;
    esiProcessResult_t processingResult;
    size_t nextElementToProcess_;
    size_t nextElementToProcess() const;
    void nextElementToProcess(size_t const &);
    bool finishedProcessing() const;
    void processStep(int dovars);
};

MEMPROXY_CLASS_INLINE(esiSequence)

#endif /* SQUID_ESISEQUENCE_H */
