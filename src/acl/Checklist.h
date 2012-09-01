/*
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

/// ACL checklist callback
typedef void ACLCB(allow_t, void *);

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
     * Start a non-blocking (async) check for a list of allow/deny rules.
     * Each rule comes with a list of ACLs.
     *
     * The callback specified will be called with the result of the check.
     *
     * The first rule where all ACLs match wins. If there is such a rule,
     * the result becomes that rule keyword (ACCESS_ALLOWED or ACCESS_DENIED).
     *
     * If there are rules but all ACL lists mismatch, an implicit rule is used.
     * Its result is the negation of the keyword of the last seen rule.
     *
     * Some ACLs may stop the check prematurely by setting an exceptional
     * check result (e.g., ACCESS_AUTH_REQUIRED) instead of declaring a
     * match or mismatch.
     *
     * If there are no rules to check at all, the result becomes ACCESS_DUNNO.
     * Calling this method with no rules to check wastes a lot of CPU cycles
     * and will result in a DBG_CRITICAL debugging message.
     */
    void nonBlockingCheck(ACLCB * callback, void *callback_data);

    /**
     * Perform a blocking (immediate) check for a list of allow/deny rules.
     * Each rule comes with a list of ACLs.
     *
     * The first rule where all ACLs match wins. If there is such a rule,
     * the result becomes that rule keyword (ACCESS_ALLOWED or ACCESS_DENIED).
     *
     * If there are rules but all ACL lists mismatch, an implicit rule is used
     * Its result is the negation of the keyword of the last seen rule.
     *
     * Some ACLs may stop the check prematurely by setting an exceptional
     * check result (e.g., ACCESS_AUTH_REQUIRED) instead of declaring a
     * match or mismatch.
     *
     * Some ACLs may require an async lookup which is prohibited by this
     * method. In this case, the exceptional check result of ACCESS_DUNNO is
     * immediately returned.
     *
     * If there are no rules to check at all, the result becomes ACCESS_DUNNO.
     */
    allow_t const & fastCheck();

    /**
     * Perform a blocking (immediate) check whether a list of ACLs matches.
     * This method is meant to be used with squid.conf ACL-driven options that
     * lack allow/deny keywords and are tested one ACL list at a time. Whether
     * the checks for other occurrences of the same option continue after this
     * call is up to the caller and option semantics.
     *
     * If all ACLs match, the result becomes ACCESS_ALLOWED.
     *
     * If all ACLs mismatch, the result becomes ACCESS_DENIED.
     *
     * Some ACLs may stop the check prematurely by setting an exceptional
     * check result (e.g., ACCESS_AUTH_REQUIRED) instead of declaring a
     * match or mismatch.
     *
     * Some ACLs may require an async lookup which is prohibited by this
     * method. In this case, the exceptional check result of ACCESS_DUNNO is
     * immediately returned.
     *
     * If there are no ACLs to check at all, the result becomes ACCESS_ALLOWED.
     */
    allow_t const & fastCheck(const ACLList * list);

    // whether the last checked ACL of the current rule needs
    // an async operation to determine whether there was a match
    bool asyncNeeded() const;
    bool asyncInProgress() const;
    void asyncInProgress(bool const);

    /// whether markFinished() was called
    bool finished() const;
    /// called when no more ACLs should be checked; sets the final answer and
    /// prints a debugging message explaining the reason for that answer
    void markFinished(const allow_t &newAnswer, const char *reason);

    const allow_t &currentAnswer() const { return allow_; }

    void changeState(AsyncState *);
    AsyncState *asyncState() const;

    // XXX: ACLs that need request or reply have to use ACLFilledChecklist and
    // should do their own checks so that we do not have to povide these two
    // for ACL::checklistMatches to use
    virtual bool hasRequest() const = 0;
    virtual bool hasReply() const = 0;

private:
    /// Calls non-blocking check callback with the answer and destroys self.
    void checkCallback(allow_t answer);

    void checkAccessList();
    void checkForAsync();

public:
    const acl_access *accessList;

    ACLCB *callback;
    void *callback_data;

    /**
     * Performs non-blocking check starting with the current rule.
     * Used by nonBlockingCheck() to initiate the checks and by
     * async operation callbacks to resume checks after the async
     * operation updates the current Squid state. See nonBlockingCheck()
     * for details on final result determination.
     */
    void matchNonBlocking();

private: /* internal methods */
    /// possible outcomes when trying to match a single ACL node in a list
    typedef enum { nmrMatch, nmrMismatch, nmrFinished, nmrNeedsAsync }
    NodeMatchingResult;

    /// prepare for checking ACLs; called once per check
    void preCheck(const char *what);
    bool matchAclList(const ACLList * list, bool const fast);
    bool matchNodes(const ACLList * head, bool const fast);
    NodeMatchingResult matchNode(const ACLList &node, bool const fast);
    void calcImplicitAnswer(const allow_t &lastSeenAction);

    bool async_;
    bool finished_;
    allow_t allow_;
    AsyncState *state_;

    bool checking_;
    bool checking() const;
    void checking (bool const);

    bool callerGone();
};

#endif /* SQUID_ACLCHECKLIST_H */
