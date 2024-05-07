/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 28    Access Control
 *
 * This file contains ACL routines that are not part of the
 * Acl::Node class, nor any other class yet, and that need to be
 * factored into appropriate places. They are here to reduce
 * unneeded dependencies between the Acl::Node class and the rest
 * of squid.
 */

#include "squid.h"
#include "acl/AclDenyInfoList.h"
#include "acl/Gadgets.h"
#include "acl/Tree.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "errorpage.h"
#include "globals.h"
#include "HttpRequest.h"
#include "SquidConfig.h"
#include "src/sbuf/Stream.h"

#include <set>
#include <algorithm>

using AclSet = std::set<Acl::Node *>;
/// Accumulates all ACLs to facilitate their clean deletion despite reuse.
static AclSet *RegisteredAcls; // TODO: Remove when ACLs are refcounted

err_type
FindDenyInfoPage(const Acl::Answer &answer, const bool redirect_allowed)
{
    if (!answer.lastCheckedName) {
        debugs(28, 3, "ERR_NONE because access was denied without evaluating ACLs");
        return ERR_NONE;
    }

    const auto &name = *answer.lastCheckedName;

    for (auto A = Config.denyInfoList; A; A = A->next) {
        if (!redirect_allowed && strchr(A->err_page_name, ':') ) {
            debugs(28, 8, "Skip '" << A->err_page_name << "' 30x redirects not allowed as response here.");
            continue;
        }

        for (const auto &aclName: A->acl_list) {
            if (aclName.cmp(name) == 0) {
                debugs(28, 8, "matched " << name << "; returning " << A->err_page_id << ' ' << A->err_page_name);
                return A->err_page_id;
            }
        }
    }

    debugs(28, 8, "no match for " << name << (Config.denyInfoList ? "" : "; no deny_info rules"));
    return ERR_NONE;
}

bool
aclIsProxyAuth(const std::optional<SBuf> &name)
{
    if (!name) {
        debugs(28, 3, "no; caller did not supply an ACL name");
        return false;
    }

    if (const auto a = Acl::Node::FindByName(*name)) {
        debugs(28, 5, "returning " << a->isProxyAuth() << " for ACL " << *name);
        return a->isProxyAuth();
    }

    debugs(28, 3, "WARNING: Called for nonexistent ACL " << *name);
    return false;
}

/* maex@space.net (05.09.96)
 *    get the info for redirecting "access denied" to info pages
 *      TODO (probably ;-)
 *      currently there is no optimization for
 *      - more than one deny_info line with the same url
 *      - a check, whether the given acl really is defined
 *      - a check, whether an acl is added more than once for the same url
 */

void
aclParseDenyInfoLine(AclDenyInfoList ** head)
{
    char *t = nullptr;
    AclDenyInfoList *B;
    AclDenyInfoList **T;

    /* first expect a page name */

    if ((t = ConfigParser::NextToken()) == nullptr) {
        debugs(28, DBG_CRITICAL, "aclParseDenyInfoLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "ERROR: aclParseDenyInfoLine: missing 'error page' parameter.");
        return;
    }

    const auto A = new AclDenyInfoList(t, ConfigParser::CurrentLocation());

    /* next expect a list of ACL names */
    while ((t = ConfigParser::NextToken())) {
        A->acl_list.emplace_back(t);
    }

    if (A->acl_list.empty()) {
        debugs(28, DBG_CRITICAL, "aclParseDenyInfoLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "aclParseDenyInfoLine: deny_info line contains no ACL's, skipping");
        delete A;
        return;
    }

    for (B = *head, T = head; B; T = &B->next, B = B->next)

        ;   /* find the tail */
    *T = A;
}

void
aclParseAccessLine(const char *directive, ConfigParser &, acl_access **treep)
{
    /* first expect either 'allow' or 'deny' */
    const char *t = ConfigParser::NextToken();

    if (!t) {
        debugs(28, DBG_CRITICAL, "aclParseAccessLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "ERROR: aclParseAccessLine: missing 'allow' or 'deny'.");
        return;
    }

    auto action = Acl::Answer(ACCESS_DUNNO);
    if (!strcmp(t, "allow"))
        action = Acl::Answer(ACCESS_ALLOWED);
    else if (!strcmp(t, "deny"))
        action = Acl::Answer(ACCESS_DENIED);
    else {
        debugs(28, DBG_CRITICAL, "aclParseAccessLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "aclParseAccessLine: expecting 'allow' or 'deny', got '" << t << "'.");
        return;
    }

    const int ruleId = ((treep && *treep) ? (*treep)->childrenCount() : 0) + 1;

    Acl::AndNode *rule = new Acl::AndNode;
    rule->context(ToSBuf(directive, '#', ruleId), config_input_line);
    rule->lineParse();
    if (rule->empty()) {
        debugs(28, DBG_CRITICAL, "aclParseAccessLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "aclParseAccessLine: Access line contains no ACL's, skipping");
        delete rule;
        return;
    }

    /* Append to the end of this list */

    assert(treep);
    if (!*treep) {
        *treep = new Acl::Tree;
        (*treep)->context(SBuf(directive), config_input_line);
    }

    (*treep)->add(rule, action);

    /* We lock _acl_access structures in ACLChecklist::matchNonBlocking() */
}

// aclParseAclList does not expect or set actions (cf. aclParseAccessLine)
size_t
aclParseAclList(ConfigParser &, Acl::Tree **treep, const char *label)
{
    // accommodate callers unable to convert their ACL list context to string
    if (!label)
        label = "...";

    Acl::AndNode *rule = new Acl::AndNode;
    rule->context(ToSBuf('(', cfg_directive, ' ', label, " line)"), config_input_line);
    const auto aclCount = rule->lineParse();

    // We want a cbdata-protected Tree (despite giving it only one child node).
    Acl::Tree *tree = new Acl::Tree;
    tree->add(rule);
    tree->context(ToSBuf(cfg_directive, ' ', label), config_input_line);

    assert(treep);
    assert(!*treep);
    *treep = tree;

    return aclCount;
}

void
aclRegister(Acl::Node *acl)
{
    if (!acl->registered) {
        if (!RegisteredAcls)
            RegisteredAcls = new AclSet;
        RegisteredAcls->insert(acl);
        acl->registered = true;
    }
}

/// remove registered acl from the centralized deletion set
static
void
aclDeregister(Acl::Node *acl)
{
    if (acl->registered) {
        if (RegisteredAcls)
            RegisteredAcls->erase(acl);
        acl->registered = false;
    }
}

/*********************/
/* Destroy functions */
/*********************/

/// called to delete ALL Acls.
void
aclDestroyAcls(Acl::Node ** head)
{
    *head = nullptr; // Config.aclList
    if (AclSet *acls = RegisteredAcls) {
        debugs(28, 8, "deleting all " << acls->size() << " ACLs");
        while (!acls->empty()) {
            auto *acl = *acls->begin();
            // We use centralized deletion (this function) so ~Acl::Node should not
            // delete other ACLs, but we still deregister first to prevent any
            // accesses to the being-deleted Acl::Node via RegisteredAcls.
            assert(acl->registered); // make sure we are making progress
            aclDeregister(acl);
            delete acl;
        }
    }
}

void
aclDestroyAclList(ACLList **list)
{
    debugs(28, 8, "aclDestroyAclList: invoked");
    assert(list);
    delete *list;
    *list = nullptr;
}

void
aclDestroyAccessList(acl_access ** list)
{
    assert(list);
    if (*list)
        debugs(28, 3, "destroying: " << *list << ' ' << (*list)->name);
    delete *list;
    *list = nullptr;
}

/* maex@space.net (06.09.1996)
 *    destroy an AclDenyInfoList */

void
aclDestroyDenyInfoList(AclDenyInfoList ** list)
{
    AclDenyInfoList *a = nullptr;
    AclDenyInfoList *a_next = nullptr;

    debugs(28, 8, "aclDestroyDenyInfoList: invoked");

    for (a = *list; a; a = a_next) {
        a_next = a->next;
        delete a;
    }

    *list = nullptr;
}

