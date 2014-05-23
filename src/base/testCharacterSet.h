#ifndef SQUID_BASE_TESTCHARACTERSET_H
#define SQUID_BASE_TESTCHARACTERSET_H

#define SQUID_UNIT_TEST 1

#include <cppunit/extensions/HelperMacros.h>

class testCharacterSet : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testCharacterSet );
    CPPUNIT_TEST( CharacterSetConstruction );
    CPPUNIT_TEST( CharacterSetAdd );
    CPPUNIT_TEST( CharacterSetAddRange );
    CPPUNIT_TEST( CharacterSetConstants );
    CPPUNIT_TEST( CharacterSetUnion );
    CPPUNIT_TEST_SUITE_END();

protected:
    void CharacterSetConstruction();
    void CharacterSetAdd();
    void CharacterSetAddRange();
    void CharacterSetConstants();
    void CharacterSetUnion();
};

#endif /* SQUID_BASE_TESTCHARACTERSET_H */
