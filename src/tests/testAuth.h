
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

