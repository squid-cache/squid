/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/Uri.h"
#include "CacheManager.h"
#include "compat/cppunit.h"
#include "mgr/Action.h"
#include "mgr/Registration.h"
#include "sbuf/Stream.h"
#include "Store.h"
#include "unitTestMain.h"

#include <cppunit/TestAssert.h>
/*
 * test the CacheManager implementation
 */

class TestCacheManager : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestCacheManager);
    CPPUNIT_TEST(testCreate);
    CPPUNIT_TEST(testRegister);
    CPPUNIT_TEST(testParseUrl);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testCreate();
    void testRegister();
    void testParseUrl();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestCacheManager );

/// Provides test code access to CacheManager internal symbols
class CacheManagerInternals : public CacheManager
{
public:
    /// checks CacheManager parsing of the given valid URL
    void testValidUrl(const AnyP::Uri &);

    /// checks CacheManager parsing of the given invalid URL
    /// \param problem a bad part of the URL or its description
    void testInvalidUrl(const AnyP::Uri &, const char *problem);
};

void
CacheManagerInternals::testValidUrl(const AnyP::Uri &url)
{
    CPPUNIT_ASSERT_NO_THROW(ParseUrl(url));
}

void
CacheManagerInternals::testInvalidUrl(const AnyP::Uri &url, const char *const problem)
{
    CPPUNIT_ASSERT_THROW_MESSAGE(problem, ParseUrl(url), TextException);
}

/// customizes our test setup
class MyTestProgram: public TestProgram
{
public:
    /* TestProgram API */
    void startup() override;
};

void
MyTestProgram::startup()
{
    Mem::Init();
    AnyP::UriScheme::Init();
}

/*
 * Test creating a CacheManager
 */
void
TestCacheManager::testCreate()
{
    CacheManager::GetInstance(); //it's a singleton..
}

/* an action to register */
static void
dummy_action(StoreEntry * sentry)
{
    sentry->flags=1;
}

/*
 * registering an action makes it findable.
 */
void
TestCacheManager::testRegister()
{
    CacheManager *manager=CacheManager::GetInstance();
    CPPUNIT_ASSERT(manager != nullptr);

    Mgr::RegisterAction("sample", "my sample", &dummy_action, Mgr::Protected::no, Mgr::Atomic::no, Mgr::Format::informal);
    Mgr::Action::Pointer action = manager->createNamedAction("sample");
    CPPUNIT_ASSERT(action != nullptr);

    const Mgr::ActionProfile::Pointer profile = action->command().profile;
    CPPUNIT_ASSERT(profile != nullptr);
    CPPUNIT_ASSERT(profile->creator != nullptr);
    CPPUNIT_ASSERT_EQUAL(false, profile->isPwReq);
    CPPUNIT_ASSERT_EQUAL(false, profile->isAtomic);
    CPPUNIT_ASSERT_EQUAL(Mgr::Format::informal, profile->format);
    CPPUNIT_ASSERT_EQUAL(Mgr::Format::informal, action->format());
    CPPUNIT_ASSERT_EQUAL(String("sample"), String(action->name()));

    StoreEntry *sentry=new StoreEntry();
    sentry->createMemObject();
    sentry->flags=0x25; //arbitrary test value
    action->run(sentry, false);
    CPPUNIT_ASSERT_EQUAL(1,(int)sentry->flags);
}

void
TestCacheManager::testParseUrl()
{
    auto *mgr = static_cast<CacheManagerInternals *>(CacheManager::GetInstance());
    CPPUNIT_ASSERT(mgr != nullptr);

    std::vector<AnyP::ProtocolType> validSchemes = {
        AnyP::PROTO_HTTP,
        AnyP::PROTO_HTTPS,
        AnyP::PROTO_FTP
    };

    AnyP::Uri mgrUrl;
    mgrUrl.host("localhost");
    mgrUrl.port(3128);

    const std::vector<const char *> validActions = {
        "",
        "menu"
    };

    const std::vector<const char *> invalidActions = {
        "INVALID" // any unregistered name
    };

    const auto &prefix = CacheManager::WellKnownUrlPathPrefix();

    assert(prefix.length());
    const auto insufficientPrefix = prefix.substr(0, prefix.length()-1);

    for (const auto &scheme : validSchemes) {
        mgrUrl.setScheme(scheme);

        // Check that the parser rejects URLs that lack the full prefix prefix.
        // These negative tests log "Squid BUG: assurance failed" ERRORs because
        // they violate CacheManager::ParseUrl()'s ForSomeCacheManager()
        // precondition.
        for (const auto *action : validActions) {
            SBuf bits;
            bits.append(insufficientPrefix);
            bits.append(action);
            mgrUrl.path(bits);
            mgr->testInvalidUrl(mgrUrl, "insufficient prefix");
        }

        // Check that the parser accepts valid URLs.
        for (const auto action: validActions) {
            SBuf bits;
            bits.append(prefix);
            bits.append(action);
            mgrUrl.path(bits);
            mgr->testValidUrl(mgrUrl);
        }

        // Check that the parser rejects unknown actions
        for (const auto *action : invalidActions) {
            SBuf bits;
            bits.append(prefix);
            bits.append(action);
            mgrUrl.path(bits);
            auto msg = ToSBuf("action '", action, "' not found");
            mgr->testInvalidUrl(mgrUrl, msg.c_str());
        }

    }
}

int
main(int argc, char *argv[])
{
    return MyTestProgram().run(argc, argv);
}

