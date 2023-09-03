/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/Uri.h"
#include "CacheManager.h"
#include "mgr/Action.h"
#include "Store.h"
#include "testCacheManager.h"
#include "unitTestMain.h"

#include <cppunit/TestAssert.h>

CPPUNIT_TEST_SUITE_REGISTRATION( testCacheManager );

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
    try {
        (void)ParseUrl(url);
    } catch (...) {
        std::cerr << "\nFAIL: " << url <<
                  Debug::Extra << "error: " << CurrentException << "\n";
        CPPUNIT_FAIL("rejected a valid URL");
    }
}

void
CacheManagerInternals::testInvalidUrl(const AnyP::Uri &url, const char *const problem)
{
    try {
        (void)ParseUrl(url);
        std::cerr << "\nFAIL: " << url <<
                  Debug::Extra << "error: should be rejected due to '" << problem << "'\n";
    } catch (const TextException &) {
        return; // success -- the parser signaled bad input
    }
    CPPUNIT_FAIL("failed to reject an invalid URL");
}

void testCacheManager::setUp()
{
    Mem::Init();
    AnyP::UriScheme::Init();
}

/*
 * Test creating a CacheManager
 */
void
testCacheManager::testCreate()
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
testCacheManager::testRegister()
{
    CacheManager *manager=CacheManager::GetInstance();
    CPPUNIT_ASSERT(manager != nullptr);

    manager->registerProfile("sample", "my sample", &dummy_action, false, false);
    Mgr::Action::Pointer action = manager->createNamedAction("sample");
    CPPUNIT_ASSERT(action != nullptr);

    const Mgr::ActionProfile::Pointer profile = action->command().profile;
    CPPUNIT_ASSERT(profile != nullptr);
    CPPUNIT_ASSERT(profile->creator != nullptr);
    CPPUNIT_ASSERT_EQUAL(false, profile->isPwReq);
    CPPUNIT_ASSERT_EQUAL(false, profile->isAtomic);
    CPPUNIT_ASSERT_EQUAL(String("sample"), String(action->name()));

    StoreEntry *sentry=new StoreEntry();
    sentry->flags=0x25; //arbitrary test value
    action->run(sentry, false);
    CPPUNIT_ASSERT_EQUAL(1,(int)sentry->flags);
}

void
testCacheManager::testParseUrl()
{
    auto *mgr = static_cast<CacheManagerInternals *>(CacheManager::GetInstance());
    CPPUNIT_ASSERT(mgr != nullptr);

    std::vector<AnyP::ProtocolType> validSchemes = {
        AnyP::PROTO_CACHE_OBJECT,
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

    const std::vector<const char *> validParams = {
        "",
        "?",
        "?&",
        "?&&&&&&&&&&&&",
        "?foo=bar",
        "?0123456789=bar",
        "?foo=bar&",
        "?foo=bar&&&&",
        "?&foo=bar",
        "?&&&&foo=bar",
        "?&foo=bar&",
        "?&&&&foo=bar&&&&",
        "?foo=?_weird?~`:[]stuff&bar=okay&&&&&&",
        "?intlist=1",
        "?intlist=1,2,3,4,5",
        "?string=1a",
        "?string=1,2,3,4,z",
        "?string=1,2,3,4,[0]",
        "?intlist=1,2,3,4,5&string=1,2,3,4,y"
    };

    const std::vector<const char *> invalidParams = {
        "?/",
        "?foo",
        "?/foo",
        "?foo/",
        "?foo=",
        "?foo=&",
        "?=foo",
        "? foo=bar",
        "? &",
        "?& ",
        "?=&",
        "?&=",
        "? &&&",
        "?& &&",
        "?&& &",
        "?=&&&",
        "?&=&&",
        "?&&=&"
    };

    const std::vector<const char *> validFragments = {
        "",
        "#",
        "##",
        "#?a=b",
        "#fragment"
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
            for (const auto *param : validParams) {
                for (const auto *frag : validFragments) {
                    SBuf bits;
                    bits.append(insufficientPrefix);
                    bits.append(action);
                    bits.append(param);
                    bits.append(frag);
                    mgrUrl.path(bits);
                    mgr->testInvalidUrl(mgrUrl, "insufficient prefix");
                }
            }
        }

        // Check that the parser accepts valid URLs.
        for (const auto action: validActions) {
            for (const auto param: validParams) {
                for (const auto frag: validFragments) {
                    SBuf bits;
                    bits.append(prefix);
                    bits.append(action);
                    bits.append(param);
                    bits.append(frag);
                    mgrUrl.path(bits);
                    mgr->testValidUrl(mgrUrl);
                }
            }
        }

        // Check that the parser rejects URLs with invalid parameters.
        for (const auto action: validActions) {
            for (const auto invalidParam: invalidParams) {
                for (const auto frag: validFragments) {
                    SBuf bits;
                    bits.append(prefix);
                    bits.append(action);
                    bits.append(invalidParam);
                    bits.append(frag);
                    mgrUrl.path(bits);
                    mgr->testInvalidUrl(mgrUrl, invalidParam);
                }
            }
        }
    }
}

