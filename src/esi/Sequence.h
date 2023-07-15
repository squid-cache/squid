/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#ifndef SQUID_ESISEQUENCE_H
#define SQUID_ESISEQUENCE_H

#include "esi/Element.h"
#include "mem/forward.h"

/* esiSequence */

class esiSequence : public ESIElement
{
    MEMPROXY_CLASS(esiSequence);

public:
    esiSequence(esiTreeParentPtr, bool = false);
    ~esiSequence() override;

    void render(ESISegment::Pointer) override;
    bool addElement (ESIElement::Pointer) override;
    esiProcessResult_t process (int dovars) override;
    void provideData (ESISegment::Pointer, ESIElement*) override;
    bool mayFail () const override;
    void wontFail();
    void fail(ESIElement *, char const *anError = nullptr) override;
    void makeCachableElements(esiSequence const &old);
    Pointer makeCacheable() const override;
    void makeUsableElements(esiSequence const &old, ESIVarState &);
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const override;

    Esi::Elements elements; /* unprocessed or rendered nodes */
    size_t processedcount;

    struct {
        int dovars:1; /* for esiVar */
    } flags;
    void finish() override;

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

