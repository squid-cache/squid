/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"

#define STUB_API "acl/"
#include "tests/STUB.h"

#include "acl/forward.h"
#include "acl/Tree.h"

#include "acl/Gadgets.h"
size_t aclParseAclList(ConfigParser &, ACLList **, const char *) STUB_RETVAL(0)
void aclDestroyAclList(ACLList **) STUB
const Acl::Tree &Acl::ToTree(const TreePointer *) STUB_RETREF(Acl::Tree)

#include "acl/Checklist.h"
ACLChecklist::ACLChecklist() STUB
ACLChecklist::~ACLChecklist() STUB
const Acl::Answer &ACLChecklist::fastCheck() STUB_RETREF(Acl::Answer)
const Acl::Answer &ACLChecklist::fastCheck(const ACLList *) STUB_RETREF(Acl::Answer)

