/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "icmp/net_db.h"
#include "unitTestMain.h"

class TestNetDb : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestNetDb);
    /* note the statement here and then the actual prototype below */
    CPPUNIT_TEST(testConstruct);
    CPPUNIT_TEST_SUITE_END();

public:
protected:
    void testConstruct();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestNetDb );

void
TestNetDb::testConstruct()
{
    // default construct and destruct
    {
        netdbEntry T;
        CPPUNIT_ASSERT_EQUAL(T.network[0], '\0');
        CPPUNIT_ASSERT_EQUAL(0, T.pings_sent);
        CPPUNIT_ASSERT_EQUAL(0, T.pings_recv);
        CPPUNIT_ASSERT_EQUAL(0.0, T.hops);
        CPPUNIT_ASSERT_EQUAL(1.0, T.rtt);
        CPPUNIT_ASSERT_EQUAL(static_cast<time_t>(0), T.next_ping_time);
        CPPUNIT_ASSERT_EQUAL(static_cast<time_t>(0), T.last_use_time);
        CPPUNIT_ASSERT_EQUAL(0, T.link_count);
        CPPUNIT_ASSERT_EQUAL(static_cast<net_db_name*>(nullptr), T.hosts);
        CPPUNIT_ASSERT_EQUAL(static_cast<net_db_peer*>(nullptr), T.peers);
        CPPUNIT_ASSERT_EQUAL(0, T.n_peers_alloc);
        CPPUNIT_ASSERT_EQUAL(0, T.n_peers);
    }

    // new and delete operations
    {
        netdbEntry *T = new netdbEntry;
        CPPUNIT_ASSERT_EQUAL(T->network[0], '\0');
        CPPUNIT_ASSERT_EQUAL(0, T->pings_sent);
        CPPUNIT_ASSERT_EQUAL(0, T->pings_recv);
        CPPUNIT_ASSERT_EQUAL(0.0, T->hops);
        CPPUNIT_ASSERT_EQUAL(1.0, T->rtt);
        CPPUNIT_ASSERT_EQUAL(static_cast<time_t>(0), T->next_ping_time);
        CPPUNIT_ASSERT_EQUAL(static_cast<time_t>(0), T->last_use_time);
        CPPUNIT_ASSERT_EQUAL(0, T->link_count);
        CPPUNIT_ASSERT_EQUAL(static_cast<net_db_name*>(nullptr), T->hosts);
        CPPUNIT_ASSERT_EQUAL(static_cast<net_db_peer*>(nullptr), T->peers);
        CPPUNIT_ASSERT_EQUAL(0, T->n_peers_alloc);
        CPPUNIT_ASSERT_EQUAL(0, T->n_peers);
        delete T;
    }
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

