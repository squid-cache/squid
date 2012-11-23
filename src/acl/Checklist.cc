/*
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
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

#include "squid.h"
#include "acl/Checklist.h"
#include "Debug.h"
#include "profiler/Profiler.h"

void
ACLChecklist::matchNonBlocking()
{
    if (checking())
        return;

    if (callerGone()) {
        checkCallback(ACCESS_DUNNO); // the answer does not really matter
        return;
    }

    /** The ACL List should NEVER be NULL when calling this method.
     * Always caller should check for NULL and handle appropriate to its needs first.
     * We cannot select a sensible default for all callers here. */
    if (accessList == NULL) {
        debugs(28, DBG_CRITICAL, "SECURITY ERROR: ACL " << this << " checked with nothing to match against!!");
        checkCallback(ACCESS_DUNNO);
        return;
    }

    allow_t lastSeenKeyword = ACCESS_DUNNO;
    /* NOTE: This holds a cbdata reference to the current access_list
     * entry, not the whole list.
     */
    while (accessList != NULL) {
        /** \par
         * If the _acl_access is no longer valid (i.e. its been
         * freed because of a reconfigure), then bail with ACCESS_DUNNO.
         */

        if (!cbdataReferenceValid(accessList)) {
            cbdataReferenceDone(accessList);
            debugs(28, 4, "ACLChecklist::check: " << this << " accessList is invalid");
            checkCallback(ACCESS_DUNNO);
            return;
        }

        checking (true);
        checkAccessList();
        checking (false);

        if (asyncInProgress()) {
            return;
        }

        if (finished()) {
            /** \par
             * Either the request is allowed, denied, requires authentication.
             */
            debugs(28, 3, "ACLChecklist::check: " << this << " match found, calling back with " << currentAnswer());
            cbdataReferenceDone(accessList); /* A */
            checkCallback(currentAnswer());
            /* From here on in, this may be invalid */
            return;
        }

        lastSeenKeyword = accessList->allow;

        /*
         * Reference the next access entry
         */
        const acl_access *A = accessList;

        assert (A);

        accessList = cbdataReference(A->next);

        cbdataReferenceDone(A);
    }

    calcImplicitAnswer(lastSeenKeyword);
    checkCallback(currentAnswer());
}

bool
ACLChecklist::asyncNeeded() const
{
    return state_ != NullState::Instance();
}

bool
ACLChecklist::asyncInProgress() const
{
    return async_;
}

void
ACLChecklist::asyncInProgress(bool const newAsync)
{
    assert (!finished() && !(asyncInProgress() && newAsync));
    async_ = newAsync;
    debugs(28, 3, "ACLChecklist::asyncInProgress: " << this <<
           " async set to " << async_);
}

bool
ACLChecklist::finished() const
{
    return finished_;
}

void
ACLChecklist::markFinished(const allow_t &finalAnswer, const char *reason)
{
    assert (!finished() && !asyncInProgress());
    finished_ = true;
    allow_ = finalAnswer;
    debugs(28, 3, HERE << this << " answer " << allow_ << " for " << reason);
}

/// Called first (and once) by all checks to initialize their state
void
ACLChecklist::preCheck(const char *what)
{
    debugs(28, 3, HERE << this << " checking " << what);
    finished_ = false;
}

void
ACLChecklist::checkAccessList()
{
    debugs(28, 3, HERE << this << " checking '" << accessList->cfgline << "'");
    /* does the current AND clause match */
    if (matchAclList(accessList->aclList, false))
        markFinished(accessList->allow, "first matching rule won");

    // If we are not finished() here, the caller must distinguish between
    // slow async calls and pure rule mismatches using asyncInProgress().
}

void
ACLChecklist::checkForAsync()
{
    asyncState()->checkForAsync(this);
}

// ACLFilledChecklist overwrites this to unclock something before we
// "delete this"
void
ACLChecklist::checkCallback(allow_t answer)
{
    ACLCB *callback_;
    void *cbdata_;
    debugs(28, 3, "ACLChecklist::checkCallback: " << this << " answer=" << answer);

    callback_ = callback;
    callback = NULL;

    if (cbdataReferenceValidDone(callback_data, &cbdata_))
        callback_(answer, cbdata_);

    delete this;
}

/// An ACLChecklist::matchNodes() wrapper to simplify profiling.
bool
ACLChecklist::matchAclList(const ACLList * head, bool const fast)
{
    // TODO: remove by using object con/destruction-based PROF_* macros.
    PROF_start(aclMatchAclList);
    const bool result = matchNodes(head, fast);
    PROF_stop(aclMatchAclList);
    return result;
}

/** Returns true if and only if there was a match. If false is returned:
    finished() indicates an error or exception of some kind, while
    !finished() means there was a mismatch or an allowed slow async call.
    If async calls are allowed (i.e. 'fast' was false), then those last
    two cases can be distinguished using asyncInProgress().
*/
bool
ACLChecklist::matchNodes(const ACLList * head, bool const fast)
{
    assert(!finished());

    for (const ACLList *node = head; node; node = node->next) {

        const NodeMatchingResult resultBeforeAsync = matchNode(*node, fast);

        if (resultBeforeAsync == nmrMatch)
            continue;

        if (resultBeforeAsync == nmrMismatch || resultBeforeAsync == nmrFinished)
            return false;

        assert(resultBeforeAsync == nmrNeedsAsync);

        // Ideally, this should be inside match() itself, but that requires
        // prohibiting slow ACLs in options that do not support them.
        // TODO: rename to maybeStartAsync()?
        checkForAsync();

        // Some match() code claims that an async lookup is needed, but then
        // fails to start an async lookup when given a chance. We catch such
        // cases here and call matchNode() again, hoping that some cached data
        // prevents us from going async again.
        // This is inefficient and ugly, but fixing all match() code, including
        // the code it calls, such as ipcache_nbgethostbyname(), takes time.
        if (!asyncInProgress()) { // failed to start an async operation

            if (finished()) {
                debugs(28, 3, HERE << this << " finished after failing to go async: " << currentAnswer());
                return false; // an exceptional case
            }

            const NodeMatchingResult resultAfterAsync = matchNode(*node, true);
            // the second call disables slow checks so we cannot go async again
            assert(resultAfterAsync != nmrNeedsAsync);
            if (resultAfterAsync == nmrMatch)
                continue;

            assert(resultAfterAsync == nmrMismatch || resultAfterAsync == nmrFinished);
            return false;
        }

        assert(!finished()); // async operation is truly asynchronous
        debugs(28, 3, HERE << this << " awaiting async operation");
        return false;
    }

    debugs(28, 3, HERE << this << " success: all ACLs matched");
    return true;
}

/// Check whether a single ACL matches, returning NodeMatchingResult
ACLChecklist::NodeMatchingResult
ACLChecklist::matchNode(const ACLList &node, bool const fast)
{
    const bool nodeMatched = node.matches(this);
    const bool needsAsync = asyncNeeded();
    const bool matchFinished = finished();

    debugs(28, 3, HERE << this <<
           " matched=" << nodeMatched <<
           " async=" << needsAsync <<
           " finished=" << matchFinished);

    /* There are eight possible outcomes of the matches() call based on
       (matched, async, finished) permutations. We support these four:
       matched,!async,!finished: a match (must check next rule node)
       !matched,!async,!finished: a mismatch (whole rule fails to match)
       !matched,!async,finished: error or special condition (propagate)
       !matched,async,!finished: ACL needs to make an async call (pause)
     */

    if (nodeMatched) {
        // matches() should return false in all special cases
        assert(!needsAsync && !matchFinished);
        return nmrMatch;
    }

    if (matchFinished) {
        // we cannot be done and need an async call at the same time
        assert(!needsAsync);
        debugs(28, 3, HERE << this << " exception: " << currentAnswer());
        return nmrFinished;
    }

    if (!needsAsync) {
        debugs(28, 3, HERE << this << " simple mismatch");
        return nmrMismatch;
    }

    /* we need an async call */

    if (fast) {
        changeState(NullState::Instance()); // disable async checks
        markFinished(ACCESS_DUNNO, "async required but prohibited");
        debugs(28, 3, HERE << this << " DUNNO because cannot async");
        return nmrFinished;
    }

    debugs(28, 3, HERE << this << " going async");
    return nmrNeedsAsync;
}

ACLChecklist::ACLChecklist() :
        accessList (NULL),
        callback (NULL),
        callback_data (NULL),
        async_(false),
        finished_(false),
        allow_(ACCESS_DENIED),
        state_(NullState::Instance()),
        checking_(false)
{
}

ACLChecklist::~ACLChecklist()
{
    assert (!asyncInProgress());

    cbdataReferenceDone(accessList);

    debugs(28, 4, "ACLChecklist::~ACLChecklist: destroyed " << this);
}

void
ACLChecklist::AsyncState::changeState (ACLChecklist *checklist, AsyncState *newState) const
{
    checklist->changeState(newState);
}

ACLChecklist::NullState *
ACLChecklist::NullState::Instance()
{
    return &_instance;
}

void
ACLChecklist::NullState::checkForAsync(ACLChecklist *) const
{}

ACLChecklist::NullState ACLChecklist::NullState::_instance;

void
ACLChecklist::changeState (AsyncState *newState)
{
    /* only change from null to active and back again,
     * not active to active.
     * relax this once conversion to states is complete
     * RBC 02 2003
     */
    assert (state_ == NullState::Instance() || newState == NullState::Instance());
    state_ = newState;
}

ACLChecklist::AsyncState *
ACLChecklist::asyncState() const
{
    return state_;
}

/**
 * Kick off a non-blocking (slow) ACL access list test
 *
 * NP: this should probably be made Async now.
 */
void
ACLChecklist::nonBlockingCheck(ACLCB * callback_, void *callback_data_)
{
    preCheck("slow rules");
    callback = callback_;
    callback_data = cbdataReference(callback_data_);
    matchNonBlocking();
}

allow_t const &
ACLChecklist::fastCheck(const ACLList * list)
{
    PROF_start(aclCheckFast);

    preCheck("fast ACLs");

    // assume DENY/ALLOW on mis/matches due to not having acl_access object
    if (matchAclList(list, true))
        markFinished(ACCESS_ALLOWED, "all ACLs matched");
    else if (!finished())
        markFinished(ACCESS_DENIED, "ACL mismatched");
    PROF_stop(aclCheckFast);
    return currentAnswer();
}

/* Warning: do not cbdata lock this here - it
 * may be static or on the stack
 */
allow_t const &
ACLChecklist::fastCheck()
{
    PROF_start(aclCheckFast);

    preCheck("fast rules");

    allow_t lastSeenKeyword = ACCESS_DUNNO;
    debugs(28, 5, "aclCheckFast: list: " << accessList);
    const acl_access *acl = cbdataReference(accessList);
    while (acl != NULL && cbdataReferenceValid(acl)) {
        // on a match, finish
        if (matchAclList(acl->aclList, true))
            markFinished(acl->allow, "first matching rule won");

        // if finished (on a match or in exceptional cases), stop
        if (finished()) {
            cbdataReferenceDone(acl);
            PROF_stop(aclCheckFast);
            return currentAnswer();
        }

        // on a mismatch, try the next access rule
        lastSeenKeyword = acl->allow;
        const acl_access *A = acl;
        acl = cbdataReference(acl->next);
        cbdataReferenceDone(A);
    }

    // There were no rules to match or no rules matched
    calcImplicitAnswer(lastSeenKeyword);
    PROF_stop(aclCheckFast);

    return currentAnswer();
}

/// When no rules matched, the answer is the inversion of the last seen rule
/// action (or ACCESS_DUNNO if the reversal is not possible). The caller
/// should set lastSeenAction to ACCESS_DUNNO if there were no rules to see.
void
ACLChecklist::calcImplicitAnswer(const allow_t &lastSeenAction)
{
    allow_t implicitRuleAnswer = ACCESS_DUNNO;
    if (lastSeenAction == ACCESS_DENIED) // reverse last seen "deny"
        implicitRuleAnswer = ACCESS_ALLOWED;
    else if (lastSeenAction == ACCESS_ALLOWED) // reverse last seen "allow"
        implicitRuleAnswer = ACCESS_DENIED;
    // else we saw no rules and will respond with ACCESS_DUNNO

    debugs(28, 3, HERE << this << " NO match found, last action " <<
           lastSeenAction << " so returning " << implicitRuleAnswer);
    markFinished(implicitRuleAnswer, "implicit rule won");
}

bool
ACLChecklist::checking() const
{
    return checking_;
}

void
ACLChecklist::checking (bool const newValue)
{
    checking_ = newValue;
}

bool
ACLChecklist::callerGone()
{
    return !cbdataReferenceValid(callback_data);
}
