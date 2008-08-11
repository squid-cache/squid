#define SQUID_UNIT_TEST 1

#include "squid.h"
#include <cppunit/TestAssert.h>

#include "Mem.h"
#include "testCacheManager.h"
#include "CacheManager.h"


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
    CacheManager();
}

/* an action to register */
static void
dummy_action(StoreEntry * sentry)
{}

/*
 * registering an action makes it findable.
 */
void
testCacheManager::testRegister()
{
    CacheManager manager;
    manager.registerAction("sample", "my sample", &dummy_action, false, false);
    CacheManagerAction *anAction = manager.findAction("sample");
    CPPUNIT_ASSERT_EQUAL(String("sample"), String(anAction->action));
    CPPUNIT_ASSERT_EQUAL(String("my sample"), String(anAction->desc));
    CPPUNIT_ASSERT_EQUAL(&dummy_action, anAction->handler);
    CPPUNIT_ASSERT_EQUAL(0, (int)anAction->flags.pw_req);
    CPPUNIT_ASSERT_EQUAL(0, (int)anAction->flags.atomic);
}
