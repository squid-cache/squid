/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "testClpMap.h"
#include "unitTestMain.h"

#include "SquidConfig.h"



CPPUNIT_TEST_SUITE_REGISTRATION( testClpMap );

class SquidConfig Config;

void
testClpMap::addData(testMap &m, int numElems, int base)
{
    for (int j = base+numElems-1; j > base; --j ) {
        m.add(std::to_string(j), j);
    }
}