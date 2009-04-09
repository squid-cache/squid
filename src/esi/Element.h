/*
 * $Id$
 *
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
 */

#ifndef SQUID_ESIELEMENT_H
#define SQUID_ESIELEMENT_H

#include "RefCount.h"
#include "esi/Segment.h"

typedef enum {
    ESI_PROCESS_COMPLETE = 0,
    ESI_PROCESS_PENDING_WONTFAIL = 1,
    ESI_PROCESS_PENDING_MAYFAIL = 2,
    ESI_PROCESS_FAILED = 3
} esiProcessResult_t;

class ESIElement;

struct esiTreeParent : public RefCountable {
    virtual void provideData (ESISegment::Pointer data, ESIElement * source) {
        /* make abstract when all functionality complete */
        assert (0);
    }

    virtual void fail(ESIElement * source, char const *reason = NULL) {}

    virtual ~esiTreeParent() {}
};

typedef RefCount<esiTreeParent> esiTreeParentPtr;

class ESIVarState;

class ESIElement : public esiTreeParent
{

public:
    typedef RefCount<ESIElement> Pointer;

    /* the types we have */
    enum ESIElementType_t {
        ESI_ELEMENT_NONE,
        ESI_ELEMENT_INCLUDE,
        ESI_ELEMENT_COMMENT,
        ESI_ELEMENT_REMOVE,
        ESI_ELEMENT_TRY,
        ESI_ELEMENT_ATTEMPT,
        ESI_ELEMENT_EXCEPT,
        ESI_ELEMENT_VARS,
        ESI_ELEMENT_CHOOSE,
        ESI_ELEMENT_WHEN,
        ESI_ELEMENT_OTHERWISE,
        ESI_ELEMENT_ASSIGN
    };
    static ESIElementType_t IdentifyElement (const char *);
    virtual bool addElement(ESIElement::Pointer) {
        /* Don't accept children */
        debugs(86,5, "ESIElement::addElement: Failed for " << this);
        return false;
    }

    virtual void render (ESISegment::Pointer) = 0;
    /* process this element */
    virtual esiProcessResult_t process (int dovars) {
        debugs(86,5, "esiProcessComplete: Processed " << this);
        return ESI_PROCESS_COMPLETE;
    }

    virtual bool mayFail() const {
        return true;
    }

    virtual Pointer makeCacheable() const = 0;
    virtual Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const = 0;

    /* The top level no longer needs this element */
    virtual void finish() = 0;
};

#endif /* SQUID_ESIELEMENT_H */
