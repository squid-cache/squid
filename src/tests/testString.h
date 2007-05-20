
#ifndef SQUID_SRC_TEST_STRING_H
#define SQUID_SRC_TEST_STRING_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the store framework
 */

class testString : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testString );
    CPPUNIT_TEST( testDefaults );
        /* boolean helper tests */
    CPPUNIT_TEST( testCmpDefault );
    CPPUNIT_TEST( testCmpEmptyString );
    CPPUNIT_TEST( testCmpNotEmptyDefault );

    CPPUNIT_TEST( testBooleans );
    CPPUNIT_TEST( testAppend );
    CPPUNIT_TEST( testAssignments );
    CPPUNIT_TEST( testAccess );
    CPPUNIT_TEST( testCstrMethods );
    CPPUNIT_TEST( testSearch );
    CPPUNIT_TEST_SUITE_END();

public:

protected:

    /* std::string API */
    void testDefaults();
    void testCmpDefault();
    void testCmpEmptyString();
    void testCmpNotEmptyDefault();
    void testBooleans();
    void testAppend();
    void testAssignments();
    void testAccess();
    void testCstrMethods();
    void testSearch();
};

#endif
