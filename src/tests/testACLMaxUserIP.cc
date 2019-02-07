/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_AUTH

#include "acl/Acl.h"
#include "auth/AclMaxUserIp.h"
#include "auth/UserRequest.h"
#include "ConfigParser.h"
#include "testACLMaxUserIP.h"
#include "unitTestMain.h"

#include <stdexcept>

CPPUNIT_TEST_SUITE_REGISTRATION( testACLMaxUserIP );

void
testACLMaxUserIP::testDefaults()
{
    ACLMaxUserIP anACL("max_user_ip");
    /* 0 is not a valid maximum, so we start at 0 */
    CPPUNIT_ASSERT_EQUAL(0,anACL.getMaximum());
    /* and we have no option to turn strict OFF, so start ON. */
    CPPUNIT_ASSERT_EQUAL(false, static_cast<bool>(anACL.beStrict));
    /* an unparsed acl must not be valid - there is no sane default */
    CPPUNIT_ASSERT_EQUAL(false,anACL.valid());
}

void
testACLMaxUserIP::setUp()
{
    CPPUNIT_NS::TestFixture::setUp();
    Acl::RegisterMaker("max_user_ip", [](Acl::TypeName name)->ACL* { return new ACLMaxUserIP(name); });
}

void
testACLMaxUserIP::testParseLine()
{
    /* a config line to pass with a lead-in token to seed the parser. */
    char * line = xstrdup("test max_user_ip -s 1");
    /* seed the parser */
    ConfigParser::SetCfgLine(line);
    ACL *anACL = NULL;
    ConfigParser LegacyParser;
    ACL::ParseAclLine(LegacyParser, &anACL);
    ACLMaxUserIP *maxUserIpACL = dynamic_cast<ACLMaxUserIP *>(anACL);
    CPPUNIT_ASSERT(maxUserIpACL);
    if (maxUserIpACL) {
        /* we want a maximum of one, and strict to be true */
        CPPUNIT_ASSERT_EQUAL(1, maxUserIpACL->getMaximum());
        CPPUNIT_ASSERT_EQUAL(true, static_cast<bool>(maxUserIpACL->beStrict));
        /* the acl must be vaid */
        CPPUNIT_ASSERT_EQUAL(true, maxUserIpACL->valid());
    }
    delete anACL;
    xfree(line);
}

#endif /* USE_AUTH */

