/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/Tree.h"
#include "Debug.h"
#include "profiler/Profiler.h"

#include <algorithm>

/// common parts of nonBlockingCheck() and resumeNonBlockingCheck()
bool
ACLChecklist::prepNonBlocking()
{
    assert(accessList);

    if (callerGone()) {
        checkCallback(ACCESS_DUNNO); // the answer does not really matter
        return false;
    }

    /** \par
     * If the accessList is no longer valid (i.e. its been
     * freed because of a reconfigure), then bail with ACCESS_DUNNO.
     */

    if (!cbdataReferenceValid(accessList)) {
        cbdataReferenceDone(accessList);
        debugs(28, 4, "ACLChecklist::check: " << this << " accessList is invalid");
        checkCallback(ACCESS_DUNNO);
        return false;
    }

    return true;
}

void
ACLChecklist::completeNonBlocking()
{
    assert(!asyncInProgress());

    if (!finished())
        calcImplicitAnswer();

    cbdataReferenceDone(accessList);
    checkCallback(currentAnswer());
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

    // concurrent checks using the same Checklist are not supported
    assert(!occupied_);
    occupied_ = true;
    asyncLoopDepth_ = 0;

    AclMatchedName = NULL;
    finished_ = false;
}

bool
ACLChecklist::matchChild(const Acl::InnerNode *current, Acl::Nodes::const_iterator pos, const ACL *child)
{
    assert(current && child);

    // Remember the current tree location to prevent "async loop" cases where
    // the same child node wants to go async more than once.
    matchLoc_ = Breadcrumb(current, pos);
    asyncLoopDepth_ = 0;

    // if there are any breadcrumbs left, then follow them on the way down
    bool result = false;
    if (matchPath.empty()) {
        result = child->matches(this);
    } else {
        const Breadcrumb top(matchPath.top());
        assert(child == top.parent);
        matchPath.pop();
        result = top.parent->resumeMatchingAt(this, top.position);
    }

    if (asyncInProgress()) {
        // We get here for node N that called goAsync() and then, as the call
        // stack unwinds, for the nodes higher in the ACL tree that led to N.
        matchPath.push(Breadcrumb(current, pos));
    } else {
        asyncLoc_.clear();
    }

    matchLoc_.clear();
    return result;
}

bool
ACLChecklist::goAsync(AsyncState *state)
{
    assert(state);
    assert(!asyncInProgress());
    assert(matchLoc_.parent);

    // TODO: add a once-in-a-while WARNING about fast directive using slow ACL?
    if (!asyncCaller_) {
        debugs(28, 2, this << " a fast-only directive uses a slow ACL!");
        return false;
    }

    // TODO: add a once-in-a-while WARNING about async loops?
    if (matchLoc_ == asyncLoc_) {
        debugs(28, 2, this << " a slow ACL resumes by going async again! (loop #" << asyncLoopDepth_ << ")");
        // external_acl_type may cause async auth lookup plus its own async check
        // which has the appearance of a loop. Allow some retries.
        // TODO: make it configurable and check BH retry attempts vs this check?
        if (asyncLoopDepth_ > 5)
            return false;
    }

    asyncLoc_ = matchLoc_; // prevent async loops
    ++asyncLoopDepth_;

    asyncStage_ = asyncStarting;
    changeState(state);
    state->checkForAsync(this); // this is supposed to go async

    // Did AsyncState object actually go async? If not, tell the caller.
    if (asyncStage_ != asyncStarting) {
        assert(asyncStage_ == asyncFailed);
        asyncStage_ = asyncNone; // sanity restored
        return false;
    }

    // yes, we must pause until the async callback calls resumeNonBlockingCheck
    asyncStage_ = asyncRunning;
    return true;
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

    // not really meaningful just before delete, but here for completeness sake
    occupied_ = false;

    delete this;
}

ACLChecklist::ACLChecklist() :
    accessList (NULL),
    callback (NULL),
    callback_data (NULL),
    asyncCaller_(false),
    occupied_(false),
    finished_(false),
    allow_(ACCESS_DENIED),
    asyncStage_(asyncNone),
    state_(NullState::Instance()),
    asyncLoopDepth_(0)
{
}

ACLChecklist::~ACLChecklist()
{
    assert (!asyncInProgress());

    changeAcl(nullptr);

    debugs(28, 4, "ACLChecklist::~ACLChecklist: destroyed " << this);
}

ACLChecklist::NullState *
ACLChecklist::NullState::Instance()
{
    return &_instance;
}

void
ACLChecklist::NullState::checkForAsync(ACLChecklist *) const
{
    assert(false); // or the Checklist will never get out of the async state
}

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
    asyncCaller_ = true;

    /** The ACL List should NEVER be NULL when calling this method.
     * Always caller should check for NULL and handle appropriate to its needs first.
     * We cannot select a sensible default for all callers here. */
    if (accessList == NULL) {
        debugs(28, DBG_CRITICAL, "SECURITY ERROR: ACL " << this << " checked with nothing to match against!!");
        checkCallback(ACCESS_DUNNO);
        return;
    }

    if (prepNonBlocking()) {
        matchAndFinish(); // calls markFinished() on success
        if (!asyncInProgress())
            completeNonBlocking();
    } // else checkCallback() has been called
}

void
ACLChecklist::resumeNonBlockingCheck(AsyncState *state)
{
    assert(asyncState() == state);
    changeState(NullState::Instance());

    if (asyncStage_ == asyncStarting) { // oops, we did not really go async
        asyncStage_ = asyncFailed; // goAsync() checks for that
        // Do not fall through to resume checks from the async callback. Let
        // the still-pending(!) goAsync() notice and notify its caller instead.
        return;
    }
    assert(asyncStage_ == asyncRunning);
    asyncStage_ = asyncNone;

    assert(!matchPath.empty());

    if (!prepNonBlocking())
        return; // checkCallback() has been called

    if (!finished())
        matchAndFinish();

    if (asyncInProgress())
        assert(!matchPath.empty()); // we have breadcrumbs to resume matching
    else
        completeNonBlocking();
}

/// performs (or resumes) an ACL tree match and, if successful, sets the action
void
ACLChecklist::matchAndFinish()
{
    bool result = false;
    if (matchPath.empty()) {
        result = accessList->matches(this);
    } else {
        const Breadcrumb top(matchPath.top());
        matchPath.pop();
        result = top.parent->resumeMatchingAt(this, top.position);
    }

    if (result) // the entire tree matched
        markFinished(accessList->winningAction(), "match");
}

allow_t const &
ACLChecklist::fastCheck(const Acl::Tree * list)
{
    PROF_start(aclCheckFast);

    preCheck("fast ACLs");
    asyncCaller_ = false;

    // Concurrent checks are not supported, but sequential checks are, and they
    // may use a mixture of fastCheck(void) and fastCheck(list) calls.
    const Acl::Tree * const savedList = changeAcl(list);

    // assume DENY/ALLOW on mis/matches due to action-free accessList
    // matchAndFinish() takes care of the ALLOW case
    if (accessList && cbdataReferenceValid(accessList))
        matchAndFinish(); // calls markFinished() on success
    if (!finished())
        markFinished(ACCESS_DENIED, "ACLs failed to match");

    changeAcl(savedList);
    occupied_ = false;
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
    asyncCaller_ = false;

    debugs(28, 5, "aclCheckFast: list: " << accessList);
    const Acl::Tree *acl = cbdataReference(accessList);
    if (acl != NULL && cbdataReferenceValid(acl)) {
        matchAndFinish(); // calls markFinished() on success

        // if finished (on a match or in exceptional cases), stop
        if (finished()) {
            cbdataReferenceDone(acl);
            occupied_ = false;
            PROF_stop(aclCheckFast);
            return currentAnswer();
        }

        // fall through for mismatch handling
    }

    // There were no rules to match or no rules matched
    calcImplicitAnswer();
    cbdataReferenceDone(acl);
    occupied_ = false;
    PROF_stop(aclCheckFast);

    return currentAnswer();
}

/// When no rules matched, the answer is the inversion of the last rule
/// action (or ACCESS_DUNNO if the reversal is not possible).
void
ACLChecklist::calcImplicitAnswer()
{
    const allow_t lastAction = (accessList && cbdataReferenceValid(accessList)) ?
                               accessList->lastAction() : allow_t(ACCESS_DUNNO);
    allow_t implicitRuleAnswer = ACCESS_DUNNO;
    if (lastAction == ACCESS_DENIED) // reverse last seen "deny"
        implicitRuleAnswer = ACCESS_ALLOWED;
    else if (lastAction == ACCESS_ALLOWED) // reverse last seen "allow"
        implicitRuleAnswer = ACCESS_DENIED;
    // else we saw no rules and will respond with ACCESS_DUNNO

    debugs(28, 3, HERE << this << " NO match found, last action " <<
           lastAction << " so returning " << implicitRuleAnswer);
    markFinished(implicitRuleAnswer, "implicit rule won");
}

bool
ACLChecklist::callerGone()
{
    return !cbdataReferenceValid(callback_data);
}

bool
ACLChecklist::bannedAction(const allow_t &action) const
{
    const bool found = std::find(bannedActions_.begin(), bannedActions_.end(), action) != bannedActions_.end();
    debugs(28, 5, "Action '" << action << "/" << action.kind << (found ? "' is " : "' is not") << " banned");
    return found;
}

void
ACLChecklist::banAction(const allow_t &action)
{
    bannedActions_.push_back(action);
}

