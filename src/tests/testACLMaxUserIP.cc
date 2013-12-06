#define SQUID_UNIT_TEST 1

#include "squid.h"

#if USE_AUTH

#include "auth/AclMaxUserIp.h"
#include "ConfigParser.h"
#include "testACLMaxUserIP.h"

#if HAVE_STDEXCEPT
#include <stdexcept>
#endif

CPPUNIT_TEST_SUITE_REGISTRATION( testACLMaxUserIP );

void
testACLMaxUserIP::testDefaults()
{
    ACLMaxUserIP anACL("max_user_ip");
    /* 0 is not a valid maximum, so we start at 0 */
    CPPUNIT_ASSERT_EQUAL(0,anACL.getMaximum());
    /* and we have no option to turn strict OFF, so start ON. */
    CPPUNIT_ASSERT_EQUAL(0,anACL.getStrict());
    /* an unparsed acl must not be valid - there is no sane default */
    CPPUNIT_ASSERT_EQUAL(false,anACL.valid());
}

void
testACLMaxUserIP::testParseLine()
{
    /* a config line to pass with a lead-in token to seed the parser. */
    char * line = xstrdup("-s 1");
    /* seed the parser */
    ConfigParser::SetCfgLine(line);
    ACLMaxUserIP anACL("max_user_ip");
    anACL.parse();
    /* we want a maximum of one, and strict to be true */
    CPPUNIT_ASSERT_EQUAL(1,anACL.getMaximum());
    CPPUNIT_ASSERT_EQUAL(1,anACL.getStrict());
    /* the acl must be vaid */
    CPPUNIT_ASSERT_EQUAL(true,anACL.valid());
    xfree(line);
}

#endif /* USE_AUTH */
