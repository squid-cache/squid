/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ESIELEMENT_H
#define SQUID_ESIELEMENT_H

#include "base/RefCount.h"
#include "Debug.h"
#include "esi/Segment.h"

#include <vector>

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

/// ESI protocol types and operators
namespace Esi {

/// an ordered set of ESI elements
typedef std::vector<ESIElement::Pointer> Elements;

} // namespace Esi

/// Call finish() and set to nil the given element. Element may already be nil.
/// When element is part of a set, use pos to indicate position/ID
/// for debugging.
extern void FinishAnElement(ESIElement::Pointer &, int pos = -1);

// for all elements call finish() and set Pointer to nil
extern void FinishAllElements(Esi::Elements &);

#endif /* SQUID_ESIELEMENT_H */

