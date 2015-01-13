/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_SBUFFINDTEST_H
#define SQUID_SRC_TEST_SBUFFINDTEST_H

#include "SBuf.h"

#include <set>
#include <string>

/// Generates and executes a [configurable] large number of SBuf::*find()
/// test cases using random strings. Reports detected failures.
class SBufFindTest
{
public:
    SBufFindTest();

    void run(); ///< generates and executes cases using configuration params

    /* test configuration parameters; can be optionally set before run() */
    int caseLimit; ///< approximate caseCount limit
    int errorLimit; ///< errorCount limit
    unsigned int randomSeed; ///< pseudo-random sequence choice
    /// whether to report only one failed test case per "category"
    bool hushSimilar;
    /// approximate maximum generated hay string length
    SBuf::size_type maxHayLength;

    /// Supported algorithms for placing needle in the hay.
    typedef enum { placeBeginning, placeMiddle, placeEnd, placeNowhere,
                   placeEof
                 } Placement; // placeLast marker must terminate
protected:

    static SBuf RandomSBuf(const int length);
    void nextLen(SBuf::size_type &len, const SBuf::size_type max);
    void placeNeedle(const SBuf &cleanHay);

    void testAllMethods();
    void testFindDefs();
    void testFind();
    void testRFindDefs();
    void testRFind();
    void testFindCharDefs();
    void testFindChar();
    void testRFindCharDefs();
    void testRFindChar();
    void testFindFirstOf();

    std::string posKey() const;
    std::string placementKey() const;

    bool resultsMatch() const;
    void checkResults(const char *method);
    void handleFailure(const char *method);

private:
    /* test case parameters */
    SBuf theSBufHay; ///< the string to be searched
    SBuf theSBufNeedle; ///< the string to be found
    SBuf::size_type thePos; ///< search position limit
    Placement thePlacement; ///< where in the hay the needle is placed
    std::string::size_type theStringPos; ///< thePos converted to std::string::size_type
    std::string theStringHay; ///< theHay converted to std::string
    std::string theStringNeedle; ///< theNeedle converted to std::string

    /// needle pos w/o thePos restrictions; used for case categorization
    std::string::size_type theBareNeedlePos;

    /* test case results */
    std::string::size_type theFindString;
    SBuf::size_type theFindSBuf;
    std::string theReportFunc;
    std::string theReportNeedle;
    std::string theReportPos;
    char theReportQuote;

    /* test progress indicators */
    int caseCount;  ///< cases executed so far
    int errorCount; ///< total number of failed test cases so far
    int reportCount; ///< total number of test cases reported so far
    std::set<std::string> failedCats; ///< reported failed categories
};

typedef SBufFindTest::Placement Placement;

#endif

