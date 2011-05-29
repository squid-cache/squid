#define SQUID_UNIT_TEST 1

#include "squid.h"
#include "testACLMaxUserIP.h"
#include "auth/AclMaxUserIp.h"

#if HAVE_STDEXCEPT
#include <stdexcept>
#endif

CPPUNIT_TEST_SUITE_REGISTRATION( testACLMaxUserIP );

// Stubs so this will build.
#include "event.h"
void
eventAdd(const char *name, EVH * func, void *arg, double when, int, bool cbdata)
{
// CALLED as setUp no-op
//    fatal("eventAdd. Not implemented.");
}

void
testACLMaxUserIP::testDefaults()
{
    ACLMaxUserIP anACL("max_user_ip");
    /* 0 is not a valid maximum, so we start at 0 */
    CPPUNIT_ASSERT(anACL.getMaximum() == 0);
    /* and we have no option to turn strict OFF, so start ON. */
    CPPUNIT_ASSERT(anACL.getStrict() == false);
    /* an unparsed acl must not be valid - there is no sane default */
    CPPUNIT_ASSERT(!anACL.valid());
}


void
testACLMaxUserIP::testParseLine()
{
    /* a config line to pass with a lead-in token to seed the parser. */
    char * line = xstrdup("token -s 1");
    /* seed the parser */
    strtok(line, w_space);
    ACLMaxUserIP anACL("max_user_ip");
    anACL.parse();
    /* we want a maximum of one, and strict to be true */
    CPPUNIT_ASSERT(anACL.getMaximum() == 1);
    CPPUNIT_ASSERT(anACL.getStrict() == true);
    /* the acl must be vaid */
    CPPUNIT_ASSERT(anACL.valid());
    xfree(line);
}
