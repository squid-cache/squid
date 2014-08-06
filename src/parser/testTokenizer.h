#ifndef SQUID_TESTTOKENIZER_H_
#define SQUID_TESTTOKENIZER_H_

#include <cppunit/extensions/HelperMacros.h>

class testTokenizer : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testTokenizer );
    CPPUNIT_TEST ( testCharacterSet );
    CPPUNIT_TEST ( testTokenizerPrefix );
    CPPUNIT_TEST ( testTokenizerSkip );
    CPPUNIT_TEST ( testTokenizerToken );
    CPPUNIT_TEST ( testTokenizerInt64 );
    CPPUNIT_TEST_SUITE_END();

protected:
    void testTokenizerPrefix();
    void testTokenizerSkip();
    void testTokenizerToken();
    void testCharacterSet();
    void testTokenizerInt64();
};

#endif /* SQUID_TESTTOKENIZER_H_ */
