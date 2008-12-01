/*
 * $Id: ACLChecklist.cc,v 1.42.2.1 2008/02/27 10:41:16 amosjeffries Exp $
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
#include "ACLChecklist.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "authenticate.h"
#include "ACLProxyAuth.h"
#include "client_side.h"
#include "AuthUserRequest.h"

int
ACLChecklist::authenticated()
{
    http_hdr_type headertype;

    if (NULL == request) {
        fatal ("requiresRequest SHOULD have been true for this ACL!!");
        return 0;
    } else if (request->flags.accelerated) {
        /* WWW authorization on accelerated requests */
        headertype = HDR_AUTHORIZATION;
    } else if (request->flags.transparent) {
        debugs(28, 1, "ACHChecklist::authenticated: authentication not applicable on transparently intercepted requests.");
        return -1;
    } else {
        /* Proxy authorization on proxy requests */
        headertype = HDR_PROXY_AUTHORIZATION;
    }

    /* get authed here */
    /* Note: this fills in auth_user_request when applicable */
    /*
     * DPW 2007-05-08
     * tryToAuthenticateAndSetAuthUser used to try to lock and
     * unlock auth_user_request on our behalf, but it was too
     * ugly and hard to follow.  Now we do our own locking here.
     *
     * I'm not sure what tryToAuthenticateAndSetAuthUser does when
     * auth_user_request is set before calling.  I'm tempted to
     * unlock and set it to NULL, but it seems safer to save the
     * pointer before calling and unlock it afterwards.  If the
     * pointer doesn't change then its a no-op.
     */
    AuthUserRequest *old_auth_user_request = auth_user_request;
    auth_acl_t result = AuthUserRequest::tryToAuthenticateAndSetAuthUser (&auth_user_request, headertype, request, conn(), src_addr);
    if (auth_user_request)
	AUTHUSERREQUESTLOCK(auth_user_request, "ACLChecklist");
    AUTHUSERREQUESTUNLOCK(old_auth_user_request, "old ACLChecklist");
    switch (result) {

    case AUTH_ACL_CANNOT_AUTHENTICATE:
        debugs(28, 4, "aclMatchAcl: returning  0 user authenticated but not authorised.");
        return 0;

    case AUTH_AUTHENTICATED:

        return 1;
        break;

    case AUTH_ACL_HELPER:
        debugs(28, 4, "aclMatchAcl: returning 0 sending credentials to helper.");
        changeState (ProxyAuthLookup::Instance());
        return 0;

    case AUTH_ACL_CHALLENGE:
        debugs(28, 4, "aclMatchAcl: returning 0 sending authentication challenge.");
        changeState (ProxyAuthNeeded::Instance());
        return 0;

    default:
        fatal("unexpected authenticateAuthenticate reply\n");
        return 0;
    }
}

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
        debugs(28, 0, "SECURITY ERROR: ACL " << this << " checked with nothing to match against!!");
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

void
ACLChecklist::checkCallback(allow_t answer)
{
    PF *callback_;
    void *cbdata_;
    debugs(28, 3, "ACLChecklist::checkCallback: " << this << " answer=" << answer);

    /* During reconfigure, we can end up not finishing call
     * sequences into the auth code */

    if (auth_user_request) {
        /* the checklist lock */
	AUTHUSERREQUESTUNLOCK(auth_user_request, "ACLChecklist");
        /* it might have been connection based */
        assert(conn() != NULL);
	/*
	 * DPW 2007-05-08
	 * yuck, this make me uncomfortable.  why do this here?
	 * ConnStateData will do its own unlocking.
	 */
	AUTHUSERREQUESTUNLOCK(conn()->auth_user_request, "conn via ACLChecklist");
        conn()->auth_type = AUTH_BROKEN;
    }

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

CBDATA_CLASS_INIT(ACLChecklist);

void *
ACLChecklist::operator new (size_t size)
{
    assert (size == sizeof(ACLChecklist));
    CBDATA_INIT_TYPE(ACLChecklist);
    ACLChecklist *result = cbdataAlloc(ACLChecklist);
    return result;
}

void
ACLChecklist::operator delete (void *address)
{
    ACLChecklist *t = static_cast<ACLChecklist *>(address);
    cbdataFree(t);
}

ACLChecklist::ACLChecklist() : accessList (NULL), my_port (0), request (NULL),
        reply (NULL),
        auth_user_request (NULL),
#if SQUID_SNMP
        snmp_community(NULL),
#endif
        callback (NULL),
        callback_data (NULL),
        extacl_entry (NULL),
        conn_(NULL),
        async_(false),
        finished_(false),
        allow_(ACCESS_DENIED),
        state_(NullState::Instance()),
        destinationDomainChecked_(false),
        sourceDomainChecked_(false),
        lastACLResult_(false)
{

    memset (&src_addr, '\0', sizeof (struct IN_ADDR));

    memset (&dst_addr, '\0', sizeof (struct IN_ADDR));

    memset (&my_addr, '\0', sizeof (struct IN_ADDR));
    rfc931[0] = '\0';
}

ACLChecklist::~ACLChecklist()
{
    assert (!asyncInProgress());

    if (extacl_entry)
        cbdataReferenceDone(extacl_entry);

    HTTPMSGUNLOCK(request);

    HTTPMSGUNLOCK(reply);

    // no auth_user_request in builds without any Authentication configured
    if (auth_user_request)
        AUTHUSERREQUESTUNLOCK(auth_user_request, "ACLChecklist destructor");

    conn_ = NULL;

    cbdataReferenceDone(accessList);

    debugs(28, 4, "ACLChecklist::~ACLChecklist: destroyed " << this);
}


ConnStateData::Pointer
ACLChecklist::conn()
{
    return  conn_;
}

void
ACLChecklist::conn(ConnStateData::Pointer aConn)
{
    assert (conn() == NULL);
    conn_ = aConn;
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

    while (accessList) {
        preCheck();
        matchAclListFast(accessList->aclList);

        if (finished()) {
            PROF_stop(aclCheckFast);
            cbdataReferenceDone(accessList);
            return currentAnswer() == ACCESS_ALLOWED;
        }

        /*
         * Reference the next access entry
         */
        const acl_access *A = accessList;

        assert (A);

        accessList = cbdataReference(A->next);

        cbdataReferenceDone(A);
    }

    debugs(28, 5, "aclCheckFast: no matches, returning: " << (currentAnswer() == ACCESS_DENIED));

    PROF_stop(aclCheckFast);
    return currentAnswer() == ACCESS_DENIED;
}


bool
ACLChecklist::destinationDomainChecked() const
{
    return destinationDomainChecked_;
}

void
ACLChecklist::markDestinationDomainChecked()
{
    assert (!finished() && !destinationDomainChecked());
    destinationDomainChecked_ = true;
}

bool
ACLChecklist::sourceDomainChecked() const
{
    return sourceDomainChecked_;
}

void
ACLChecklist::markSourceDomainChecked()
{
    assert (!finished() && !sourceDomainChecked());
    sourceDomainChecked_ = true;
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

/*
 * Any ACLChecklist created by aclChecklistCreate() must eventually be
 * freed by ACLChecklist::operator delete().  There are two common cases:
 *
 * A) Using aclCheckFast():  The caller creates the ACLChecklist using
 *    aclChecklistCreate(), checks it using aclCheckFast(), and frees it
 *    using aclChecklistFree().
 *
 * B) Using aclNBCheck() and callbacks: The caller creates the
 *    ACLChecklist using aclChecklistCreate(), and passes it to
 *    aclNBCheck().  Control eventually passes to ACLChecklist::checkCallback(),
 *    which will invoke the callback function as requested by the
 *    original caller of aclNBCheck().  This callback function must
 *    *not* invoke aclChecklistFree().  After the callback function
 *    returns, ACLChecklist::checkCallback() will free the ACLChecklist using
 *    aclChecklistFree().
 */

ACLChecklist *
aclChecklistCreate(const acl_access * A, HttpRequest * request, const char *ident)
{
    ACLChecklist *checklist = new ACLChecklist;

    if (A)
        checklist->accessList = cbdataReference(A);

    if (request != NULL) {
        checklist->request = HTTPMSGLOCK(request);
        checklist->src_addr = request->client_addr;
        checklist->my_addr = request->my_addr;
        checklist->my_port = request->my_port;
    }

#if USE_IDENT
    if (ident)
        xstrncpy(checklist->rfc931, ident, USER_IDENT_SZ);

#endif

    return checklist;
}

bool
ACLChecklist::callerGone()
{
    return !cbdataReferenceValid(callback_data);
}

#ifndef _USE_INLINE_
#include "ACLChecklist.cci"
#endif
