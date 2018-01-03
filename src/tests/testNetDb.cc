/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "icmp/net_db.h"
#include "tests/testNetDb.h"
#include "unitTestMain.h"

#include <stdexcept>

CPPUNIT_TEST_SUITE_REGISTRATION( testNetDb );

void
testNetDb::testConstruct()
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

