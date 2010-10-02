#ifndef SQUID_COMPAT_TESTS_TESTPRECOMPILER_H
#define SQUID_COMPAT_TESTS_TESTPRECOMPILER_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * Test the pre-compiler directives used within Squid code actually work.
 */

class testPreCompiler : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testPreCompiler );
    CPPUNIT_TEST( testIfDef );
    CPPUNIT_TEST( testIfDefAnd );
    CPPUNIT_TEST( testIfDefOr );
    CPPUNIT_TEST_SUITE_END();

protected:
    void testIfDef();
    void testIfDefAnd();
    void testIfDefOr();
};

#endif /* SQUID_COMPAT_TESTS_TESTPRECOMPILER_H */
