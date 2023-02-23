/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_AUTH_H
#define SQUID_SRC_TEST_AUTH_H

#if USE_AUTH

#include "compat/cppunit.h"

/*
 * test the auth Config framework
 */

class TestAuth : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestAuth );
    CPPUNIT_TEST( instantiate );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void instantiate();
};

class TestAuthConfig : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestAuthConfig );
    CPPUNIT_TEST( create );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void create();
};

class TestAuthUserRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestAuthUserRequest );
    CPPUNIT_TEST( scheme );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void scheme();
    void construction();
};

#if HAVE_AUTH_MODULE_BASIC
#include "auth/basic/UserRequest.h"
class TestAuthBasicUserRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestAuthBasicUserRequest );
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
#include "auth/digest/UserRequest.h"
class TestAuthDigestUserRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestAuthDigestUserRequest );
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
#include "auth/ntlm/UserRequest.h"
class TestAuthNTLMUserRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestAuthNTLMUserRequest );
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
#include "auth/negotiate/UserRequest.h"
class TestAuthNegotiateUserRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestAuthNegotiateUserRequest );
    CPPUNIT_TEST( construction );
    CPPUNIT_TEST( username );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void construction();
    void username();
};
#endif

#endif /* USE_AUTH */
#endif /* SQUID_SRC_TEST_AUTH_H */

