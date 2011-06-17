/*
 * $Id$
 *
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

allow_t const &
ACLChecklist::currentAnswer() const
{
    return allow_;
}

void
ACLChecklist::currentAnswer(allow_t const newAnswer)
{
    allow_ = newAnswer;
}

void
ACLChecklist::check()
{
    if (checking())
        return;

    /** Deny if no rules present. */
    currentAnswer(ACCESS_DENIED);

    if (callerGone()) {
        checkCallback(currentAnswer());
        return;
    }

    /** The ACL List should NEVER be NULL when calling this method.
     * Always caller should check for NULL and handle appropriate to its needs first.
     * We cannot select a sensible default for all callers here. */
    if (accessList == NULL) {
        debugs(28, DBG_CRITICAL, "SECURITY ERROR: ACL " << this << " checked with nothing to match against!!");
        currentAnswer(ACCESS_DENIED);
        checkCallback(currentAnswer());
        return;
    }

    /* NOTE: This holds a cbdata reference to the current access_list
     * entry, not the whole list.
     */
    while (accessList != NULL) {
        /** \par
         * If the _acl_access is no longer valid (i.e. its been
         * freed because of a reconfigure), then bail on this
         * access check.  For now, return ACCESS_DENIED.
         */

        if (!cbdataReferenceValid(accessList)) {
            cbdataReferenceDone(accessList);
            debugs(28, 4, "ACLChecklist::check: " << this << " accessList is invalid");
            continue;
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

        /*
         * Reference the next access entry
         */
        const acl_access *A = accessList;

        assert (A);

        accessList = cbdataReference(A->next);

        cbdataReferenceDone(A);
    }

    /** If dropped off the end of the list return inversion of last line allow/deny action. */
    debugs(28, 3, HERE << this << " NO match found, returning " <<
           (currentAnswer() != ACCESS_DENIED ? ACCESS_DENIED : ACCESS_ALLOWED));

    checkCallback(currentAnswer() != ACCESS_DENIED ? ACCESS_DENIED : ACCESS_ALLOWED);
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
ACLChecklist::markFinished()
{
    assert (!finished() && !asyncInProgress());
    finished_ = true;
    debugs(28, 3, "ACLChecklist::markFinished: " << this <<
           " checklist processing finished");
}

void
ACLChecklist::preCheck()
{
    debugs(28, 3, "ACLChecklist::preCheck: " << this << " checking '" << accessList->cfgline << "'");
    /* what is our result on a match? */
    currentAnswer(accessList->allow);
}

void
ACLChecklist::checkAccessList()
{
    preCheck();
    /* does the current AND clause match */
    matchAclListSlow(accessList->aclList);
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
    PF *callback_;
    void *cbdata_;
    debugs(28, 3, "ACLChecklist::checkCallback: " << this << " answer=" << answer);

    callback_ = callback;
    callback = NULL;

    if (cbdataReferenceValidDone(callback_data, &cbdata_))
        callback_(answer, cbdata_);

    delete this;
}

void
ACLChecklist::matchAclListSlow(const ACLList * list)
{
    matchAclList(list, false);
}

void
ACLChecklist::matchAclList(const ACLList * head, bool const fast)
{
    PROF_start(aclMatchAclList);
    const ACLList *node = head;

    finished_ = false;

    while (node) {
        bool nodeMatched = node->matches(this);

        if (fast)
            changeState(NullState::Instance());

        if (finished()) {
            PROF_stop(aclMatchAclList);
            return;
        }

        if (!nodeMatched || state_ != NullState::Instance()) {
            debugs(28, 3, "aclmatchAclList: " << this << " returning false (AND list entry failed to match)");

            bool async = state_ != NullState::Instance();

            checkForAsync();

            bool async_in_progress = asyncInProgress();
            debugs(28, 3, "aclmatchAclList: async=" << (async ? 1 : 0) <<
                   " nodeMatched=" << (nodeMatched ? 1 : 0) <<
                   " async_in_progress=" << (async_in_progress ? 1 : 0) <<
                   " lastACLResult() = " << (lastACLResult() ? 1 : 0) <<
                   " finished() = " << finished());

            if (finished()) {
                PROF_stop(aclMatchAclList);
                return;
            }

            if (async && nodeMatched && !asyncInProgress() && lastACLResult()) {
                // async acl, but using cached response, and it was a match
                node = node->next;
                continue;
            }

            PROF_stop(aclMatchAclList);

            return;
        }

        node = node->next;
    }

    debugs(28, 3, "aclmatchAclList: " << this << " returning true (AND list satisfied)");

    markFinished();
    PROF_stop(aclMatchAclList);
}

ACLChecklist::ACLChecklist() :
        accessList (NULL),
        callback (NULL),
        callback_data (NULL),
        async_(false),
        finished_(false),
        allow_(ACCESS_DENIED),
        state_(NullState::Instance()),
        lastACLResult_(false)
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
ACLChecklist::nonBlockingCheck(PF * callback_, void *callback_data_)
{
    callback = callback_;
    callback_data = cbdataReference(callback_data_);
    check();
}

/* Warning: do not cbdata lock this here - it
 * may be static or on the stack
 */
int
ACLChecklist::fastCheck()
{
    PROF_start(aclCheckFast);
    currentAnswer(ACCESS_DENIED);
    debugs(28, 5, "aclCheckFast: list: " << accessList);
    const acl_access *acl = cbdataReference(accessList);
    while (acl != NULL && cbdataReferenceValid(acl)) {
        currentAnswer(acl->allow);
        if (matchAclListFast(acl->aclList)) {
            PROF_stop(aclCheckFast);
            cbdataReferenceDone(acl);
            return currentAnswer() == ACCESS_ALLOWED;
        }

        /*
         * Reference the next access entry
         */
        const acl_access *A = acl;
        acl = cbdataReference(acl->next);
        cbdataReferenceDone(A);
    }

    debugs(28, 5, "aclCheckFast: no matches, returning: " << (currentAnswer() == ACCESS_DENIED));

    PROF_stop(aclCheckFast);
    return currentAnswer() == ACCESS_DENIED;
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

bool
ACLChecklist::matchAclListFast(const ACLList * list)
{
    matchAclList(list, true);
    return finished();
}


