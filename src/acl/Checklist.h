/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLCHECKLIST_H
#define SQUID_ACLCHECKLIST_H

#include "acl/InnerNode.h"
#include <stack>
#include <vector>

class HttpRequest;

/// ACL checklist callback
typedef void ACLCB(Acl::Answer, void *);

/** \ingroup ACLAPI
    Base class for maintaining Squid and transaction state for access checks.
    Provides basic ACL checking methods. Its only child, ACLFilledChecklist,
    keeps the actual state data. The split is necessary to avoid exposing
    all ACL-related code to virtually Squid data types. */
class ACLChecklist
{

public:

    /// a function that initiates asynchronous ACL checks; see goAsync()
    using AsyncStarter = void (ACLFilledChecklist &, const AclNode &);

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
    Acl::Answer const & fastCheck();

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
    Acl::Answer const & fastCheck(const Acl::Tree *list);

    /// If slow lookups are allowed, switches into "async in progress" state.
    /// Otherwise, returns false; the caller is expected to handle the failure.
    bool goAsync(AsyncStarter, const AclNode &);

    /// Matches (or resumes matching of) a child node while maintaning
    /// resumption breadcrumbs if a [grand]child node goes async.
    bool matchChild(const Acl::InnerNode *parent, Acl::Nodes::const_iterator pos, const AclNode *child);

    /// Whether we should continue to match tree nodes or stop/pause.
    bool keepMatching() const { return !finished() && !asyncInProgress(); }

    /// whether markFinished() was called
    bool finished() const { return finished_; }
    /// async call has been started and has not finished (or failed) yet
    bool asyncInProgress() const { return asyncStage_ != asyncNone; }
    /// called when no more ACLs should be checked; sets the final answer and
    /// prints a debugging message explaining the reason for that answer
    void markFinished(const Acl::Answer &newAnswer, const char *reason);

    const Acl::Answer &currentAnswer() const { return answer_; }

    /// whether the action is banned or not
    bool bannedAction(const Acl::Answer &action) const;
    /// add action to the list of banned actions
    void banAction(const Acl::Answer &action);

    // XXX: ACLs that need request or reply have to use ACLFilledChecklist and
    // should do their own checks so that we do not have to povide these two
    // for AclNode::checklistMatches to use
    virtual bool hasRequest() const = 0;
    virtual bool hasReply() const = 0;
    virtual bool hasAle() const = 0;
    /// assigns uninitialized adapted_request and url ALE components
    virtual void syncAle(HttpRequest *adaptedRequest, const char *logUri) const = 0;
    /// warns if there are uninitialized ALE components and fills them
    virtual void verifyAle() const = 0;

    /// change the current ACL list
    /// \return a pointer to the old list value (may be nullptr)
    const Acl::Tree *changeAcl(const Acl::Tree *t) {
        const Acl::Tree *old = accessList;
        if (t != accessList) {
            cbdataReferenceDone(accessList);
            accessList = cbdataReference(t);
        }
        return old;
    }

private:
    /// Calls non-blocking check callback with the answer and destroys self.
    void checkCallback(Acl::Answer answer);

    void matchAndFinish();

    const Acl::Tree *accessList;
public:

    ACLCB *callback;
    void *callback_data;

    /// Resumes non-blocking check started by nonBlockingCheck() and
    /// suspended until some async operation updated Squid state.
    void resumeNonBlockingCheck();

private: /* internal methods */
    /// Position of a child node within an AclNode tree.
    class Breadcrumb
    {
    public:
        Breadcrumb(): parent(nullptr) {}
        Breadcrumb(const Acl::InnerNode *aParent, Acl::Nodes::const_iterator aPos): parent(aParent), position(aPos) {}
        bool operator ==(const Breadcrumb &b) const { return parent == b.parent && (!parent || position == b.position); }
        bool operator !=(const Breadcrumb &b) const { return !this->operator ==(b); }
        void clear() { parent = nullptr; }
        const Acl::InnerNode *parent; ///< intermediate node in the AclNode tree
        Acl::Nodes::const_iterator position; ///< child position inside parent
    };

    /// possible outcomes when trying to match a single AclNode node in a list
    typedef enum { nmrMatch, nmrMismatch, nmrFinished, nmrNeedsAsync }
    NodeMatchingResult;

    /// prepare for checking ACLs; called once per check
    void preCheck(const char *what);
    bool prepNonBlocking();
    void completeNonBlocking();
    void calcImplicitAnswer();

    bool asyncCaller_; ///< whether the caller supports async/slow ACLs
    bool occupied_; ///< whether a check (fast or non-blocking) is in progress
    bool finished_;
    Acl::Answer answer_;

    enum AsyncStage { asyncNone, asyncStarting, asyncRunning, asyncFailed };
    AsyncStage asyncStage_;
    Breadcrumb matchLoc_; ///< location of the node running matches() now
    Breadcrumb asyncLoc_; ///< currentNode_ that called goAsync()
    unsigned asyncLoopDepth_; ///< how many times the current async state has resumed

    bool callerGone();

    /// suspended (due to an async lookup) matches() in the AclNode tree
    std::stack<Breadcrumb> matchPath;
    /// the list of actions which must ignored during acl checks
    std::vector<Acl::Answer> bannedActions_;
};

#endif /* SQUID_ACLCHECKLIST_H */

