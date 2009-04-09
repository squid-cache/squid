/*
 * $Id$
 *
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
 */

#ifndef SQUID_ACLCHECKLIST_H
#define SQUID_ACLCHECKLIST_H

#include "acl/Acl.h"

/** \ingroup ACLAPI
    Base class for maintaining Squid and transaction state for access checks.
	Provides basic ACL checking methods. Its only child, ACLFilledChecklist,
	keeps the actual state data. The split is necessary to avoid exposing
    all ACL-related code to virtually Squid data types. */
class ACLChecklist
{

public:

    /**
     * State class.
     * This abstract class defines the behaviour of
     * async lookups - which can vary for different ACL types.
     * Today, every state object must be a singleton.
     * See NULLState for an example.
     *
     \note *no* state should be stored in the state object,
     * they are used to change the behaviour of the checklist, not
     * to hold information. If you need to store information in the
     * state object, consider subclassing ACLChecklist, converting it
     * to a composite, or changing the state objects from singletons to
     * refcounted objects.
     */

    class AsyncState
    {

    public:
        virtual void checkForAsync(ACLChecklist *) const = 0;
        virtual ~AsyncState() {}

    protected:
        void changeState (ACLChecklist *, AsyncState *) const;
    };

    class NullState : public AsyncState
    {

    public:
        static NullState *Instance();
        virtual void checkForAsync(ACLChecklist *) const;
        virtual ~NullState() {}

    private:
        static NullState _instance;
    };


public:
    ACLChecklist();
    virtual ~ACLChecklist();

    /**
     * Trigger off a non-blocking access check for a set of *_access options..
     * The callback specified will be called with true/false
     * when the results of the ACL tests are known.
     */
    void nonBlockingCheck(PF * callback, void *callback_data);

    /**
     * Trigger a blocking access check for a set of *_access options.
     *
     * ACLs which cannot be satisfied directly from available data are ignored.
     * This means any proxy_auth, external_acl, DNS lookups, Ident lookups etc
     * which have not already been performed and cached will not be checked.
     *
     * If there is no access list to check the default is to return DENIED.
     * However callers should perform their own check and default based on local
     * knowledge of the ACL usage rather than depend on this default.
     * That will also save on work setting up ACLChecklist fields for a no-op.
     *
     * \retval  1/true    Access Allowed
     * \retval 0/false    Access Denied
     */
    int fastCheck();

    /**
     * Trigger a blocking access check for a single ACL line (a AND b AND c).
     *
     * ACLs which cannot be satisfied directly from available data are ignored.
     * This means any proxy_auth, external_acl, DNS lookups, Ident lookups etc
     * which have not already been performed and cached will not be checked.
     *
     * \retval  1/true    Access Allowed
     * \retval 0/false    Access Denied
     */
    bool matchAclListFast(const ACLList * list);

    /**
     * Attempt to check the current checklist against current data.
     * This is the core routine behind all ACL test routines.
     * As much as possible of current tests are performed immediately
     * and the result is maybe delayed to wait for async lookups.
     *
     * When all tests are done callback is presented with one of:
     *  - ACCESS_ALLOWED     Access explicitly Allowed
     *  - ACCESS_DENIED      Access explicitly Denied
     */
    void check();

    bool asyncInProgress() const;
    void asyncInProgress(bool const);

    bool finished() const;
    void markFinished();

    allow_t const & currentAnswer() const;
    void currentAnswer(allow_t const);

    void changeState(AsyncState *);
    AsyncState *asyncState() const;

    // XXX: ACLs that need request or reply have to use ACLFilledChecklist and
    // should do their own checks so that we do not have to povide these two
    // for ACL::checklistMatches to use
    virtual bool hasRequest() const = 0;
    virtual bool hasReply() const = 0;

protected:
    virtual void checkCallback(allow_t answer);
private:
    void checkAccessList();
    void checkForAsync();

public:
    const acl_access *accessList;

    PF *callback;
    void *callback_data;

private: /* internal methods */
    void preCheck();
    void matchAclList(const ACLList * list, bool const fast);
    void matchAclListSlow(const ACLList * list);

    bool async_;
    bool finished_;
    allow_t allow_;
    AsyncState *state_;

    bool checking_;
    bool checking() const;
    void checking (bool const);

    bool lastACLResult_;
    bool callerGone();

public:
    bool lastACLResult(bool x) { return lastACLResult_ = x; }

    bool lastACLResult() const { return lastACLResult_; }
};

#endif /* SQUID_ACLCHECKLIST_H */
