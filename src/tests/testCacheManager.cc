/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
    void ParseUrl(const AnyP::Uri &u) { CacheManager::ParseUrl(u); }
};

/* init memory pools */

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
    CPPUNIT_ASSERT(manager != NULL);

    manager->registerProfile("sample", "my sample", &dummy_action, false, false);
    Mgr::Action::Pointer action = manager->createNamedAction("sample");
    CPPUNIT_ASSERT(action != NULL);

    const Mgr::ActionProfile::Pointer profile = action->command().profile;
    CPPUNIT_ASSERT(profile != NULL);
    CPPUNIT_ASSERT(profile->creator != NULL);
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

    const std::vector<const char *> validPathActions = {
        // "", // technically valid, but not supported
        "/",
        "/menu",
        // "/squid-internal-mgr", // technically valid, but not supported
        "/squid-internal-mgr/",
        "/squid-internal-mgr/menu"
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

    const std::vector<const char *> validFragments = {
        "",
        "#",
        "##",
        "#?a=b",
        "#fragment"
    };

    unsigned caseNumber = 0;
    unsigned success = 0;
    for (const auto &scheme : validSchemes) {
        mgrUrl.setScheme(scheme);

        for (const auto *action : validPathActions) {

            // all schemes except cache_object require "/squid-internal-mgr" path prefix
            if (scheme != AnyP::PROTO_CACHE_OBJECT && strlen(action) <= 19)
                continue;

            for (const auto *param : validParams) {

                for (const auto *frag : validFragments) {
                    try {
                        ++caseNumber;

                        SBuf bits;
                        bits.append(action);
                        bits.append(param);
                        bits.append(frag);
                        mgrUrl.path(bits);

                        (void)mgr->ParseUrl(mgrUrl);
                        CPPUNIT_ASSERT(++success);
                    } catch (...) {
                        std::cerr << std::endl
                                  << "FAIL: " << mgrUrl
                                  << Debug::Extra << "error: " << CurrentException << std::endl;
                        CPPUNIT_ASSERT_EQUAL(caseNumber, success);
                    }
                }
            }
        }
    }
}
