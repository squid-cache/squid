/*
 * StatHist unit test
 */

#ifndef TESTSTATHIST_H_
#define TESTSTATHIST_H_

#include <cppunit/extensions/HelperMacros.h>

class testStatHist : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testStatHist );
    CPPUNIT_TEST( testStatHistBaseEquality );
    CPPUNIT_TEST( testStatHistBaseAssignment );
    CPPUNIT_TEST( testStatHistLog );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testStatHistBaseEquality();
    void testStatHistBaseAssignment();
    void testStatHistLog();
};

#endif /* TESTSTATHIST_H_ */
