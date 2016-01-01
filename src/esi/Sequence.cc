/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#include "squid.h"
#include "Debug.h"
#include "fatal.h"

/* MS Visual Studio Projects are monolithic, so we need the following
 * #if to exclude the ESI code from compile process when not needed.
 */
#if (USE_SQUID_ESI == 1)

#include "esi/Attempt.h"
#include "esi/Except.h"
#include "esi/Literal.h"
#include "esi/Sequence.h"

class esiExcept;

esiSequence::~esiSequence ()
{
    debugs(86, 5, "esiSequence::~esiSequence " << this);
}

esiSequence::esiSequence(esiTreeParentPtr aParent, bool incrementalFlag) :
    elements(),
    processedcount(0),
    parent(aParent),
    mayFail_(true),
    failed(false),
    provideIncrementalData(incrementalFlag),
    processing(false),
    processingResult(ESI_PROCESS_COMPLETE),
    nextElementToProcess_(0)
{
    memset(&flags, 0, sizeof(flags));
}

size_t
esiSequence::nextElementToProcess() const
{
    return nextElementToProcess_;
}

void
esiSequence::nextElementToProcess(size_t const &aSizeT)
{
    nextElementToProcess_ = aSizeT;
}

bool
esiSequence::finishedProcessing() const
{
    return nextElementToProcess() >= elements.size();
}

bool
esiSequence::mayFail () const
{
    if (failed)
        return true;

    return mayFail_;
}

void
esiSequence::wontFail()
{
    assert (!failed);
    mayFail_ = false;
}

void
esiSequence::render(ESISegment::Pointer output)
{
    /* append all processed elements, and trim processed
     * and rendered elements
     */
    assert (output->next == NULL);
    debugs (86,5, "esiSequenceRender: rendering " << processedcount << " elements");

    for (size_t i = 0; i < processedcount; ++i) {
        elements[i]->render(output);
        elements.setNULL(i,i+1);
        /* FIXME: pass a ESISegment ** ? */
        output = output->tail();
    }

    elements.pop_front (processedcount);
    processedcount = 0;
    assert (output->next == NULL);
}

void
esiSequence::finish()
{
    debugs(86, 5, "esiSequence::finish: " << this << " is finished");
    elements.setNULL(0, elements.size());
    parent = NULL;
}

void
esiSequence::provideData (ESISegment::Pointer data, ESIElement *source)
{
    ESIElement::Pointer lockthis = this;

    if (processing)
        debugs(86, 5, "esiSequence::provideData: " << this << " data provided during processing");
    debugs(86, 5, "esiSequence::provideData " << this << " " << data.getRaw() << " " << source);

    /* when data is provided, the element *must* be completed */
    /* XXX: when the callback model is complete,
     * we can introduce 'finished'. And then this rule can be
     * relaxed
     */
    /* find the index */
    int index = elementIndex (source);

    assert (index >= 0);

    /* remove the current node */
    elements.setNULL(index, index+1);

    /* create a literal */
    esiLiteral *temp = new esiLiteral (data);

    /* insert the literal */
    elements[index] = temp;

    /* XXX: TODO push any pushable data upwards */
    /* fail() not done */
    if (processing)
        return;

    assert (process (flags.dovars) != ESI_PROCESS_FAILED);
}

bool
esiSequence::addElement (ESIElement::Pointer element)
{
    /* add an element to the output list */
    /* Some elements require specific parents */

    if (dynamic_cast<esiAttempt*>(element.getRaw()) ||
            dynamic_cast<esiExcept*>(element.getRaw())) {
        debugs(86, DBG_CRITICAL, "esiSequenceAdd: misparented Attempt or Except element (section 3.4)");
        return false;
    }

    /* Tie literals together for efficiency */
    if (elements.size() && dynamic_cast<esiLiteral*>(element.getRaw()) &&
            dynamic_cast<esiLiteral*>(elements[elements.size() - 1].getRaw())) {
        debugs(86, 5, "esiSequenceAdd: tying Literals " <<
               elements[elements.size() - 1].getRaw() << " and " <<
               element.getRaw() << " together");

        ESISegment::ListTransfer (((esiLiteral *)element.getRaw())->buffer,
                                  ((esiLiteral *)elements[elements.size() - 1].getRaw())->buffer);
        return true;
    }

    elements.push_back(element);
    debugs (86,3, "esiSequenceAdd: Added a new element, elements = " << elements.size());
    return true;
}

int
esiSequence::elementIndex(ESIElement::Pointer anElement) const
{
    for (size_t i = 0; i < elements.size(); ++i)
        if (elements[i] == anElement)
            return i;

    return -1;
}

void
esiSequence::processStep(int dovars)
{
    size_t elementToProcess = nextElementToProcess();
    nextElementToProcess(elementToProcess + 1);
    esiProcessResult_t tempResult = processOne(dovars, elementToProcess);

    if (processingResult < tempResult) {
        debugs(86, 5, "esiSequence::process: processingResult was " << processingResult << ", increasing to " << tempResult);
        processingResult = tempResult;
    }
}

esiProcessResult_t
esiSequence::processOne(int dovars, size_t index)
{
    debugs (86,5, "esiSequence::process " << this << " about to process element[" << index << "] " << elements[index].getRaw());

    switch (elements[index]->process(dovars)) {

    case ESI_PROCESS_COMPLETE:
        debugs(86, 5, "esiSequenceProcess: " << this << " element " << elements[index].getRaw() << " Processed OK");

        if (index == processedcount)
            /* another completely ready */
            ++processedcount;

        return ESI_PROCESS_COMPLETE;

    case ESI_PROCESS_PENDING_WONTFAIL:
        debugs(86, 5, "esiSequenceProcess: element Processed PENDING OK");

        return ESI_PROCESS_PENDING_WONTFAIL;

    case ESI_PROCESS_PENDING_MAYFAIL:
        debugs(86, 5, "eseSequenceProcess: element Processed PENDING UNKNOWN");

        return ESI_PROCESS_PENDING_MAYFAIL;

    case ESI_PROCESS_FAILED:
        debugs(86, 5, "esiSequenceProcess: element Processed FAILED");

        return ESI_PROCESS_FAILED;

    default:
        fatal ("unexpected code in esiSequence::processOne\n");

        return ESI_PROCESS_FAILED;
    }
}

esiProcessResult_t
esiSequence::process (int inheritedVarsFlag)
{
    debugs(86, 5, "esiSequence::process: " << this << " processing");

    if (processing) {
        debugs(86, 5, "esiSequence::process: " << this <<
               " reentry attempt during processing");
    }

    /* process as much of the list as we can, stopping only on
     * faliures
     */
    if (!processing || processedcount == 0)
        processingResult = ESI_PROCESS_COMPLETE;

    int dovars = inheritedVarsFlag;

    if (flags.dovars)
        dovars = 1;

    debugs(86, 5, "esiSequence::process: Processing " << this << " with" <<
           (dovars ? "" : "out") << " variable processing");

    processing = true;

    nextElementToProcess(processedcount);

    while (!finishedProcessing()) {
        processStep(dovars);

        if (!processing)
            return processingResult;

        if (processingResult == ESI_PROCESS_FAILED) {
            elements.setNULL (0, elements.size());
            failed = true;
            parent = NULL;
            processing = false;
            return processingResult;
        }
    }

    assert (processingResult != ESI_PROCESS_COMPLETE || processedcount == elements.size());

    if (processingResult == ESI_PROCESS_COMPLETE || processingResult == ESI_PROCESS_PENDING_WONTFAIL)
        wontFail();

    if (processedcount == elements.size() || provideIncrementalData) {
        ESISegment::Pointer temp(new ESISegment);
        render (temp);

        if (temp->next.getRaw() || temp->len)
            parent->provideData(temp, this);
        else
            ESISegmentFreeList (temp);
    }

    /* Depends on full parsing before processing */
    if (processedcount == elements.size())
        parent = NULL;

    debugs(86, 5, "esiSequence::process: " << this << " completed");

    processing = false;

    return processingResult;
}

void
esiSequence::fail (ESIElement *source, char const *anError)
{
    failed = true;

    if (processing) {
        debugs(86, 5, "esiSequence::fail: " << this << " failure callback during processing");
        return;
    }

    debugs(86, 5, "esiSequence::fail: " << this << " has failed.");
    parent->fail (this, anError);
    elements.setNULL(0, elements.size());
    parent = NULL;
}

esiSequence::esiSequence(esiSequence const &old) :
    processedcount(0),
    parent(NULL),
    mayFail_(old.mayFail_),
    failed(old.failed),
    provideIncrementalData(old.provideIncrementalData),
    processing(false),
    processingResult(ESI_PROCESS_COMPLETE),
    nextElementToProcess_(0)
{
    flags.dovars = old.flags.dovars;
}

void
esiSequence::makeCachableElements(esiSequence const &old)
{
    for (size_t counter = 0; counter < old.elements.size(); ++counter) {
        ESIElement::Pointer newElement = old.elements[counter]->makeCacheable();

        if (newElement.getRaw())
            assert (addElement(newElement));
    }
}

void
esiSequence::makeUsableElements(esiSequence const &old, ESIVarState &newVarState)
{
    for (size_t counter = 0; counter < old.elements.size(); ++counter) {
        ESIElement::Pointer newElement = old.elements[counter]->makeUsable (this, newVarState);

        if (newElement.getRaw())
            assert (addElement(newElement));
    }
}

ESIElement::Pointer
esiSequence::makeCacheable() const
{
    debugs(86, 5, "esiSequence::makeCacheable: Making cachable sequence from " << this);
    assert (processedcount == 0);
    assert (!failed);

    if (elements.size() == 0) {
        debugs(86, 5, "esiSequence::makeCacheable: No elements in sequence " << this << ", returning NULL");
        return NULL;
    }

    esiSequence * resultS = new esiSequence (*this);
    ESIElement::Pointer result = resultS;
    resultS->makeCachableElements(*this);
    debugs(86, 5, "esiSequence::makeCacheable: " << this << " created " << result.getRaw());
    return result;
}

ESIElement::Pointer
esiSequence::makeUsable(esiTreeParentPtr newParent, ESIVarState &newVarState) const
{
    debugs(86, 5, "esiSequence::makeUsable: Creating usable Sequence");
    assert (processedcount == 0);
    assert (!failed);

    if (elements.size() == 0) {
        debugs(86, 5, "esiSequence::makeUsable: No elements in sequence " << this << ", returning NULL");
        return NULL;
    }

    esiSequence * resultS = new esiSequence (*this);
    ESIElement::Pointer result = resultS;
    resultS->parent = newParent;
    resultS->makeUsableElements(*this, newVarState);
    return result;
}

#endif /* USE_SQUID_ESI == 1 */

