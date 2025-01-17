/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/FilledChecklist.h"
#include "acl/Tree.h"
#include "debug/Stream.h"

#include <algorithm>

/// common parts of nonBlockingCheck() and resumeNonBlockingCheck()
bool
ACLChecklist::prepNonBlocking()
{
    assert(accessList);

    if (callerGone()) {
        checkCallback("caller is gone"); // the answer does not really matter
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

    checkCallback(nullptr);
}

void
ACLChecklist::markFinished(const Acl::Answer &finalAnswer, const char *reason)
{
    assert (!finished() && !asyncInProgress());
    finished_ = true;
    answer_ = finalAnswer;
    answer_.lastCheckedName = lastCheckedName_;
    debugs(28, 3, this << " answer " << answer_ << " for " << reason);
}

/// Called first (and once) by all checks to initialize their state
void
ACLChecklist::preCheck(const char *what)
{
    debugs(28, 3, this << " checking " << what);

    // concurrent checks using the same Checklist are not supported
    assert(!occupied_);
    occupied_ = true;
    asyncLoopDepth_ = 0;

    lastCheckedName_.reset();
    finished_ = false;
}

bool
ACLChecklist::matchChild(const Acl::InnerNode * const current, const Acl::Nodes::const_iterator pos)
{
    const auto &child = *pos;
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
ACLChecklist::goAsync(AsyncStarter starter, const Acl::Node &acl)
{
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
    starter(*Filled(this), acl); // this is supposed to go async

    // Did starter() actually go async? If not, tell the caller.
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
ACLChecklist::checkCallback(const char * const abortReason)
{
    if (abortReason)
        markFinished(ACCESS_DUNNO, abortReason);
    Assure(finished());

    ACLCB *callback_;
    void *cbdata_;

    callback_ = callback;
    callback = nullptr;

    if (cbdataReferenceValidDone(callback_data, &cbdata_))
        callback_(currentAnswer(), cbdata_);

    // not really meaningful just before delete, but here for completeness sake
    occupied_ = false;

    delete this;
}

ACLChecklist::ACLChecklist() :
    accessList (nullptr),
    callback (nullptr),
    callback_data (nullptr),
    asyncCaller_(false),
    occupied_(false),
    finished_(false),
    answer_(ACCESS_DENIED),
    asyncStage_(asyncNone),
    asyncLoopDepth_(0)
{
}

ACLChecklist::~ACLChecklist()
{
    assert (!asyncInProgress());
    debugs(28, 4, "ACLChecklist::~ACLChecklist: destroyed " << this);
}

void
ACLChecklist::changeAcl(const acl_access * const replacement)
{
    accessList = replacement ? *replacement : nullptr;
}

Acl::TreePointer
ACLChecklist::swapAcl(const acl_access * const replacement)
{
    const auto old = accessList;
    changeAcl(replacement);
    return old;
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

    /** The ACL list should NEVER be NULL when calling this method.
     * Always caller should check for NULL and handle appropriate to its needs first.
     * We cannot select a sensible default for all callers here. */
    if (accessList == nullptr) {
        debugs(28, DBG_CRITICAL, "SECURITY ERROR: ACL " << this << " checked with nothing to match against!!");
        checkCallback("nonBlockingCheck() without accessList");
        return;
    }

    if (prepNonBlocking()) {
        matchAndFinish(); // calls markFinished() on success
        if (!asyncInProgress())
            completeNonBlocking();
    } // else checkCallback() has been called
}

void
ACLChecklist::resumeNonBlockingCheck()
{
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

const Acl::Answer &
ACLChecklist::fastCheck(const ACLList * const list)
{
    preCheck("fast ACLs");
    asyncCaller_ = false;

    // Concurrent checks are not supported, but sequential checks are, and they
    // may use a mixture of fastCheck(void) and fastCheck(list) calls.
    const auto savedList = swapAcl(list);

    // assume DENY/ALLOW on mis/matches due to action-free accessList
    // matchAndFinish() takes care of the ALLOW case
    if (accessList)
        matchAndFinish(); // calls markFinished() on success
    if (!finished())
        markFinished(ACCESS_DENIED, "ACLs failed to match");

    changeAcl(&savedList);
    occupied_ = false;
    return currentAnswer();
}

/* Warning: do not cbdata lock this here - it
 * may be static or on the stack
 */
Acl::Answer const &
ACLChecklist::fastCheck()
{
    preCheck("fast rules");
    asyncCaller_ = false;

    debugs(28, 5, "aclCheckFast: list: " << accessList);
    if (accessList) {
        matchAndFinish(); // calls markFinished() on success

        // if finished (on a match or in exceptional cases), stop
        if (finished()) {
            occupied_ = false;
            return currentAnswer();
        }

        // fall through for mismatch handling
    }

    // There were no rules to match or no rules matched
    calcImplicitAnswer();
    occupied_ = false;

    return currentAnswer();
}

/// When no rules matched, the answer is the inversion of the last rule
/// action (or ACCESS_DUNNO if the reversal is not possible).
void
ACLChecklist::calcImplicitAnswer()
{
    const auto lastAction = accessList ?
                            accessList->lastAction() : Acl::Answer(ACCESS_DUNNO);
    auto implicitRuleAnswer = Acl::Answer(ACCESS_DUNNO);
    if (lastAction == ACCESS_DENIED) // reverse last seen "deny"
        implicitRuleAnswer = Acl::Answer(ACCESS_ALLOWED);
    else if (lastAction == ACCESS_ALLOWED) // reverse last seen "allow"
        implicitRuleAnswer = Acl::Answer(ACCESS_DENIED);
    // else we saw no rules and will respond with ACCESS_DUNNO

    implicitRuleAnswer.implicit = true;
    debugs(28, 3, this << " NO match found, last action " <<
           lastAction << " so returning " << implicitRuleAnswer);
    markFinished(implicitRuleAnswer, "implicit rule won");
}

bool
ACLChecklist::callerGone()
{
    return !cbdataReferenceValid(callback_data);
}

bool
ACLChecklist::bannedAction(const Acl::Answer &action) const
{
    const bool found = std::find(bannedActions_.begin(), bannedActions_.end(), action) != bannedActions_.end();
    debugs(28, 5, "Action '" << action << "/" << action.kind << (found ? "' is " : "' is not") << " banned");
    return found;
}

void
ACLChecklist::banAction(const Acl::Answer &action)
{
    bannedActions_.push_back(action);
}

