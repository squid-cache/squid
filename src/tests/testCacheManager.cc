#define SQUID_UNIT_TEST 1

#include "squid.h"
#include <cppunit/TestAssert.h>

#include "Mem.h"
#include "testCacheManager.h"
#include "CacheManager.h"
#include "Store.h"


CPPUNIT_TEST_SUITE_REGISTRATION( testCacheManager );

/* stub functions to link successfully */
void
shut_down(int)
{}

void
reconfigure(int)
{}

/* end stubs */

/* init memory pools */

void testCacheManager::setUp()
{
    Mem::Init();
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

    manager->registerAction("sample", "my sample", &dummy_action, false, false);
    CacheManagerAction *anAction = manager->findAction("sample");

    CPPUNIT_ASSERT_EQUAL(0, (int)anAction->flags.pw_req);
    CPPUNIT_ASSERT_EQUAL(0, (int)anAction->flags.atomic);
    CPPUNIT_ASSERT_EQUAL(String("sample"), String(anAction->action));

    StoreEntry *sentry=new StoreEntry();
    sentry->flags=0x25; //arbitrary test value
    anAction->run(sentry);
    CPPUNIT_ASSERT_EQUAL(1,(int)sentry->flags);
}
