/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "stub_acl_libapi.cc"
#include "tests/STUB.h"

#include "acl/Acl.h"
#include "sbuf/SBuf.h"
void Acl::RegisterMaker(TypeName , Maker ) STUB
void Acl::SetKey(SBuf &, const char *, const char *) STUB
ACL* ACL::FindByName(const char *) STUB_RETVAL(nullptr)
ACL::ACL() {}
ACL::~ACL() STUB
bool ACL::valid () const STUB_RETVAL(false)
bool ACL::matches(ACLChecklist *) const STUB_RETVAL(false)
void ACL::context(const char *, const char *) STUB
void ACL::ParseAclLine(ConfigParser &, ACL **) STUB
bool ACL::isProxyAuth() const STUB_RETVAL(false)
void ACL::parseFlags() STUB
SBufList ACL::dumpOptions() STUB_RETVAL(SBufList())
int ACL::matchForCache(ACLChecklist *) STUB_RETVAL(0)
int ACL::cacheMatchAcl(dlink_list *, ACLChecklist *) STUB_RETVAL(0)

#include "acl/Gadgets.h"
void aclCacheMatchFlush(dlink_list *) STUB
err_type aclGetDenyInfoPage(AclDenyInfoList **, const char *, int ) STUB_RETVAL(ERR_NONE)
int aclIsProxyAuth(const char *) STUB_RETVAL(0)
void aclParseDenyInfoLine(AclDenyInfoList **) STUB
void aclParseAccessLine(const char *, ConfigParser &, acl_access **) STUB
size_t aclParseAclList(ConfigParser &, Acl::Tree **, const char *) STUB_RETVAL(0)
void aclRegister(ACL *) STUB
void aclDestroyAcls(ACL ** ) STUB
void aclDestroyAclList(ACLList **) STUB
void aclDestroyAccessList(acl_access **) STUB
void aclDestroyDenyInfoList(AclDenyInfoList **) STUB

#include "acl/Checklist.h"
bool ACLChecklist::prepNonBlocking() STUB_RETVAL(false)
void ACLChecklist::completeNonBlocking() STUB
void ACLChecklist::markFinished(const Acl::Answer &, const char *) STUB
void ACLChecklist::preCheck(const char *) STUB
bool ACLChecklist::matchChild(const Acl::InnerNode *, Acl::Nodes::const_iterator, const ACL *) STUB
bool ACLChecklist::goAsync(AsyncState *) STUB
void ACLChecklist::checkCallback(Acl::Answer) STUB
ACLChecklist::ACLChecklist() STUB_NOP
ACLChecklist::~ACLChecklist() STUB_NOP
static Acl::Answer anAclAnswer;
Acl::Answer const & ACLChecklist::fastCheck(const Acl::Tree *) STUB_RETVAL(anAclAnswer)
Acl::Answer const & ACLChecklist::fastCheck() STUB_RETVAL(anAclAnswer)

#include "acl/Options.h"
const Acl::Options & Acl::NoOptions() {static const Options none; return none;}
#include "acl/Acl.h"
bool ACL::requiresAle() const STUB_RETVAL(false)
bool ACL::requiresReply() const STUB_RETVAL(false)
bool ACL::requiresRequest() const STUB_RETVAL(false)
void ACL::Initialize() STUB
void ACL::operator delete(void*) STUB_NOP
