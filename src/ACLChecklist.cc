/*
 * $Id: ACLChecklist.cc,v 1.11 2003/05/17 17:35:03 hno Exp $
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
#include "authenticate.h"
#include "ACLProxyAuth.h"
#include "client_side.h"

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
        debug(28, 1) ("ACHChecklist::authenticated: authentication not applicable on transparently intercepted requests.\n");
        return -1;
    } else {
        /* Proxy authorization on proxy requests */
        headertype = HDR_PROXY_AUTHORIZATION;
    }

    /* get authed here */
    /* Note: this fills in auth_user_request when applicable */
    switch (authenticateTryToAuthenticateAndSetAuthUser(&auth_user_request, headertype, request, conn(), src_addr)) {

    case AUTH_ACL_CANNOT_AUTHENTICATE:
        debug(28, 4) ("aclMatchAcl: returning  0 user authenticated but not authorised.\n");
        return 0;

    case AUTH_AUTHENTICATED:
        return 1;
        break;

    case AUTH_ACL_HELPER:
        debug(28, 4) ("aclMatchAcl: returning 0 sending credentials to helper.\n");
        changeState (ProxyAuthLookup::Instance());
        return 0;

    case AUTH_ACL_CHALLENGE:
        debug(28, 4) ("aclMatchAcl: returning 0 sending authentication challenge.\n");
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

    /* deny if no rules present */
    currentAnswer(ACCESS_DENIED);

    /* NOTE: This holds a cbdata reference to the current access_list
     * entry, not the whole list.
     */
    while (accessList != NULL) {
        /*
         * If the _acl_access is no longer valid (i.e. its been
         * freed because of a reconfigure), then bail on this
         * access check.  For now, return ACCESS_DENIED.
         */

        if (!cbdataReferenceValid(accessList)) {
            cbdataReferenceDone(accessList);
            debug (28,4)("ACLChecklist::check: %p accessList is invalid\n", this);
            continue;
        }

        checking (true);
        checkAccessList();
        checking (false);

        if (asyncInProgress()) {
            return;
        }

        if (finished()) {
            /*
             * We are done.  Either the request
             * is allowed, denied, requires authentication.
             */
            debug(28, 3) ("ACLChecklist::check: %p match found, calling back with %d\n", this, currentAnswer());
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

    /* dropped off the end of the list */
    debug(28, 3) ("ACLChecklist::check: %p NO match found, returning %d\n", this,
                  currentAnswer() != ACCESS_DENIED ? ACCESS_DENIED : ACCESS_ALLOWED);

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
    debug (28,3)("ACLChecklist::asyncInProgress: %p async set to %d\n", this, async_);
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
    debug (28,3)("ACLChecklist::markFinished: %p checklist processing finished\n", this);
}

void
ACLChecklist::checkAccessList()
{
    debug(28, 3) ("ACLChecklist::checkAccessList: %p checking '%s'\n", this, accessList->cfgline);
    /* what is our result on a match? */
    currentAnswer(accessList->allow);
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
    debug(28, 3) ("ACLChecklist::checkCallback: %p answer=%d\n", this, answer);
    /* During reconfigure, we can end up not finishing call
     * sequences into the auth code */

    if (auth_user_request) {
        /* the checklist lock */
        authenticateAuthUserRequestUnlock(auth_user_request);
        /* it might have been connection based */
        assert(conn());
        conn()->auth_user_request = NULL;
        conn()->auth_type = AUTH_BROKEN;
        auth_user_request = NULL;
    }

    callback_ = callback;
    callback = NULL;

    if (cbdataReferenceValidDone(callback_data, &cbdata_))
        callback_(answer, cbdata_);

    delete this;
}

void
ACLChecklist::matchAclList(const acl_list * head, bool const fast)
{
    PROF_start(aclMatchAclList);
    const acl_list *node = head;

    while (node) {
        bool nodeMatched = node->matches(this);

        if (fast)
            changeState(NullState::Instance());

        if (!nodeMatched || state_ != NullState::Instance()) {
            debug(28, 3) ("aclmatchAclList: %p returning false (AND list entry failed to match)\n", this);
            checkForAsync();
            PROF_stop(aclMatchAclList);
            return;
        }

        node = node->next;
    }

    debug(28, 3) ("aclmatchAclList: %p returning true (AND list satisfied)\n", this);
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
    /* Mark result as being owned - we want the refcounter to do the delete
     * call */
    cbdataReference(result);
    return result;
}

void
ACLChecklist::operator delete (void *address)
{
    ACLChecklist *t = static_cast<ACLChecklist *>(address);
    cbdataFree(address);
    /* And allow the memory to be freed */
    cbdataReferenceDone (t);
}

void
ACLChecklist::deleteSelf() const
{
    delete this;
}

ACLChecklist::ACLChecklist() : accessList (NULL), my_port (0), request (NULL),
        reply (NULL),
        auth_user_request (NULL)
#if SQUID_SNMP
        ,snmp_community(NULL)
#endif
        , callback (NULL),
        callback_data (NULL),
        extacl_entry (NULL),
        conn_(NULL),
        async_(false),
        finished_(false),
        allow_(ACCESS_DENIED),
        state_(NullState::Instance()),
        destinationDomainChecked_(false),
        sourceDomainChecked_(false)
{

    memset (&src_addr, '\0', sizeof (struct in_addr));

    memset (&dst_addr, '\0', sizeof (struct in_addr));

    memset (&my_addr, '\0', sizeof (struct in_addr));
    rfc931[0] = '\0';
}

ACLChecklist::~ACLChecklist()
{
    assert (!asyncInProgress());

    if (extacl_entry)
        cbdataReferenceDone(extacl_entry);

    if (request)
        requestUnlink(request);

    request = NULL;

    cbdataReferenceDone(conn_);

    cbdataReferenceDone(accessList);

    debug (28,4)("ACLChecklist::~ACLChecklist: destroyed %p\n", this);
}


ConnStateData *
ACLChecklist::conn()
{
    return  conn_;
}

void
ACLChecklist::conn(ConnStateData *aConn)
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

#ifndef _USE_INLINE_
#include "ACLChecklist.cci"
#endif
