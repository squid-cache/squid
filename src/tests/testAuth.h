/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_AUTH_H
#define SQUID_SRC_TEST_AUTH_H

#if USE_AUTH

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
#include "auth/basic/UserRequest.h"
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
#include "auth/digest/UserRequest.h"
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
#include "auth/ntlm/UserRequest.h"
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
#include "auth/negotiate/UserRequest.h"
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

#endif /* USE_AUTH */
#endif /* SQUID_SRC_TEST_AUTH_H */

