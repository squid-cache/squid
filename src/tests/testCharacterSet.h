/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_TESTCHARACTERSET_H
#define SQUID_BASE_TESTCHARACTERSET_H

#include <cppunit/extensions/HelperMacros.h>

class testCharacterSet : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testCharacterSet );
    CPPUNIT_TEST( CharacterSetConstruction );
    CPPUNIT_TEST( CharacterSetAdd );
    CPPUNIT_TEST( CharacterSetAddRange );
    CPPUNIT_TEST( CharacterSetEqualityOp );
    CPPUNIT_TEST( CharacterSetConstants );
    CPPUNIT_TEST( CharacterSetUnion );
    CPPUNIT_TEST( CharacterSetSubtract );
    CPPUNIT_TEST_SUITE_END();

protected:
    void CharacterSetConstruction();
    void CharacterSetAdd();
    void CharacterSetAddRange();
    void CharacterSetConstants();
    void CharacterSetUnion();
    void CharacterSetEqualityOp();
    void CharacterSetSubtract();
};

#endif /* SQUID_BASE_TESTCHARACTERSET_H */

