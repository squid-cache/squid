
#ifndef SQUID_SRC_TEST_AUTH_H
#define SQUID_SRC_TEST_AUTH_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the auth Config framework
 */

class testAuth : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testAuth );
    CPPUNIT_TEST( instantiate );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void instantiate();
};

class testAuthConfig : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testAuthConfig );
    CPPUNIT_TEST( create );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void create();
};

class testAuthUserRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testAuthUserRequest );
    CPPUNIT_TEST( scheme );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void scheme();
    void construction();
};

#if HAVE_AUTH_MODULE_BASIC
#include "auth/basic/basicUserRequest.h"
class testAuthBasicUserRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testAuthBasicUserRequest );
    CPPUNIT_TEST( construction );
    CPPUNIT_TEST( username );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void construction();
    void username();
};
#endif

#if HAVE_AUTH_MODULE_DIGEST
#include "auth/digest/digestUserRequest.h"
class testAuthDigestUserRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testAuthDigestUserRequest );
    CPPUNIT_TEST( construction );
    CPPUNIT_TEST( username );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void construction();
    void username();
};
#endif

#if HAVE_AUTH_MODULE_NTLM
#include "auth/ntlm/ntlmUserRequest.h"
class testAuthNTLMUserRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testAuthNTLMUserRequest );
    CPPUNIT_TEST( construction );
    CPPUNIT_TEST( username );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void construction();
    void username();
};
#endif

#if HAVE_AUTH_MODULE_NEGOTIATE
#include "auth/negotiate/negotiateUserRequest.h"
class testAuthNegotiateUserRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testAuthNegotiateUserRequest );
    CPPUNIT_TEST( construction );
    CPPUNIT_TEST( username );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void construction();
    void username();
};
#endif

#endif

