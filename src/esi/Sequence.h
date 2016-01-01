/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#ifndef SQUID_ESISEQUENCE_H
#define SQUID_ESISEQUENCE_H

#include "esi/Element.h"
#include "esi/ElementList.h"
#include "mem/forward.h"

/* esiSequence */

class esiSequence : public ESIElement
{
    MEMPROXY_CLASS(esiSequence);

public:
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

    struct {
        int dovars:1; /* for esiVar */
    } flags;
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

#endif /* SQUID_ESISEQUENCE_H */

