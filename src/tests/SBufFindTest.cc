/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "tests/SBufFindTest.h"

#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/Message.h>
#include <limits>
#include <random>

/* TODO: The whole SBufFindTest class is currently implemented as a single
   CppUnit test case (because we do not want to register and report every one
   of the thousands of generated test cases). Is there a better way to
   integrate with CppUnit?
 */

SBufFindTest::SBufFindTest():
    caseLimit(std::numeric_limits<int>::max()),
    errorLimit(std::numeric_limits<int>::max()),
    hushSimilar(true),
    maxHayLength(40),
    thePos(0),
    thePlacement(placeEof),
    theStringPos(0),
    theBareNeedlePos(0),
    theFindString(0),
    theFindSBuf(0),
    theReportFunc(),
    theReportNeedle(),
    theReportPos(),
    theReportQuote('"'),
    caseCount(0),
    errorCount(0),
    reportCount(0)
{
}

void
SBufFindTest::run()
{
    for (SBuf::size_type hayLen = 0U; hayLen <= maxHayLength; nextLen(hayLen, maxHayLength)) {
        const SBuf cleanHay = RandomSBuf(hayLen);

        const SBuf::size_type maxNeedleLen = hayLen + 10;
        for (SBuf::size_type needleLen = 0U; needleLen <= maxNeedleLen; nextLen(needleLen, maxNeedleLen)) {
            theSBufNeedle = RandomSBuf(needleLen);

            for (int i = 0; i < placeEof; i++) {
                thePlacement = Placement(i);
                placeNeedle(cleanHay);

                const SBuf::size_type maxArg =
                    max(theSBufHay.length(), theSBufNeedle.length()) + 10;
                for (thePos = 0; thePos <= maxArg; nextLen(thePos, maxArg))
                    testAllMethods();

                // the special npos value is not tested as the behavior is
                //  different from std::string (where the behavior is undefined)
                //  It is ad-hoc tested in testSBuf instead
                //thePos = SBuf::npos;
                //testAllMethods();
            }
        }
    }

    if (errorCount > 0) {
        std::cerr << "Generated SBuf test cases: " << caseCount << std::endl;
        std::cerr << "\tfailed cases: " << errorCount << std::endl;
        std::cerr << "\treported cases: " << reportCount << std::endl;
        std::cerr << "Asserting because some cases failed..." << std::endl;
        CPPUNIT_ASSERT(!SBufFindTest::errorCount);
    }
}

/// tests SBuf::find(string needle)
void
SBufFindTest::testFindDefs()
{
    theFindString = theBareNeedlePos = theStringHay.find(theStringNeedle);
    theFindSBuf = theSBufHay.find(theSBufNeedle);
    checkResults("find");
}

/// tests SBuf::rfind(string needle)
void
SBufFindTest::testRFindDefs()
{
    theFindString = theBareNeedlePos = theStringHay.rfind(theStringNeedle);
    theFindSBuf = theSBufHay.rfind(theSBufNeedle);
    checkResults("rfind");
}

/// tests SBuf::find(string needle, pos)
void
SBufFindTest::testFind()
{
    theFindString = theStringHay.find(theStringNeedle, thePos);
    theBareNeedlePos = theStringHay.find(theStringNeedle);
    theFindSBuf = theSBufHay.find(theSBufNeedle, thePos);
    checkResults("find");
}

/// tests SBuf::findFirstOf(string needle, pos)
void
SBufFindTest::testFindFirstOf()
{
    theFindString = theStringHay.find_first_of(theStringNeedle, thePos);
    theBareNeedlePos = theStringHay.find_first_of(theStringNeedle);
    theFindSBuf = theSBufHay.findFirstOf(CharacterSet("cs",theSBufNeedle.c_str()), thePos);
    checkResults("find_first_of");
}

/// tests SBuf::rfind(string needle, pos)
void
SBufFindTest::testRFind()
{
    theFindString = theStringHay.rfind(theStringNeedle, thePos);
    theBareNeedlePos = theStringHay.rfind(theStringNeedle);
    theFindSBuf = theSBufHay.rfind(theSBufNeedle, thePos);
    checkResults("rfind");
}

/// tests SBuf::find(char needle)
void
SBufFindTest::testFindCharDefs()
{
    const char c = theStringNeedle[0];
    theFindString = theBareNeedlePos = theStringHay.find(c);
    theFindSBuf = theSBufHay.find(c);
    checkResults("find");
}

/// tests SBuf::find(char needle, pos)
void
SBufFindTest::testFindChar()
{
    const char c = theStringNeedle[0];
    theFindString = theStringHay.find(c, thePos);
    theBareNeedlePos = theStringHay.find(c);
    theFindSBuf = theSBufHay.find(c, thePos);
    checkResults("find");
}

/// tests SBuf::rfind(char needle)
void
SBufFindTest::testRFindCharDefs()
{
    const char c = theStringNeedle[0];
    theFindString = theBareNeedlePos = theStringHay.rfind(c);
    theFindSBuf = theSBufHay.rfind(c);
    checkResults("rfind");
}

/// tests SBuf::rfind(char needle, pos)
void
SBufFindTest::testRFindChar()
{
    const char c = theStringNeedle[0];
    theFindString = theStringHay.rfind(c, thePos);
    theBareNeedlePos = theStringHay.rfind(c);
    theFindSBuf = theSBufHay.rfind(c, thePos);
    checkResults("rfind");
}

/// whether the last SBuf and std::string find() results are the same
bool
SBufFindTest::resultsMatch() const
{
    // this method is needed because SBuf and std::string use different
    // size_types (and npos values); comparing the result values directly
    // would lead to bugs

    if (theFindString == std::string::npos && theFindSBuf == SBuf::npos)
        return true; // both npos

    // now safe to cast a non-negative SBuf result
    return theFindString == static_cast<std::string::size_type>(theFindSBuf);
}

/// called at the end of test case to update state, detect and report failures
void
SBufFindTest::checkResults(const char *method)
{
    ++caseCount;
    if (!resultsMatch())
        handleFailure(method);
}

/// helper function to convert "printable" Type to std::string
template<typename Type>
inline std::string
AnyToString(const Type &value)
{
    std::stringstream sbuf;
    sbuf << value;
    return sbuf.str();
}

#if 0
/// helper function to convert SBuf position to a human-friendly string
inline std::string
PosToString(const SBuf::size_type pos)
{
    return pos == SBuf::npos ? std::string("npos") : AnyToString(pos);
}
#endif

/// helper function to convert std::string position to a human-friendly string
inline std::string
PosToString(const std::string::size_type pos)
{
    return pos == std::string::npos ? std::string("npos") : AnyToString(pos);
}

/// tests each supported SBuf::*find() method using generated hay, needle, pos
void
SBufFindTest::testAllMethods()
{
    theStringHay = std::string(theSBufHay.rawContent(), theSBufHay.length());
    theStringNeedle = std::string(theSBufNeedle.rawContent(), theSBufNeedle.length());
    theBareNeedlePos = std::string::npos;
    const std::string reportPos = PosToString(thePos);

    // always test string search
    {
        theReportQuote = '"';
        theReportNeedle = theStringNeedle;

        theReportPos = "";
        testFindDefs();
        testRFindDefs();

        theReportPos = reportPos;
        testFind();
        testRFind();
        testFindFirstOf();
    }

    // if possible, test char search
    if (!theStringNeedle.empty()) {
        theReportQuote = '\'';
        theReportNeedle = theStringNeedle[0];

        theReportPos = "";
        testFindCharDefs();
        testRFindCharDefs();

        theReportPos = reportPos;
        testFindChar();
        testRFindChar();
    }
}

/// helper function to format a length-based key (part of case category string)
inline std::string
lengthKey(const std::string &str)
{
    if (str.length() == 0)
        return "0";
    if (str.length() == 1)
        return "1";
    return "N";
}

/// formats position key (part of the case category string)
std::string
SBufFindTest::posKey() const
{
    // the search position does not matter if needle is not in hay
    if (theBareNeedlePos == std::string::npos)
        return std::string();

    if (thePos == SBuf::npos)
        return ",npos";

    if (thePos < theBareNeedlePos)
        return ",posL"; // to the Left of the needle

    if (thePos == theBareNeedlePos)
        return ",posB"; // Beginning of the needle

    if (thePos < theBareNeedlePos + theStringNeedle.length())
        return ",posM"; // in the Middle of the needle

    if (thePos == theBareNeedlePos + theStringNeedle.length())
        return ",posE"; // at the End of the needle

    if (thePos < theStringHay.length())
        return ",posR"; // to the Right of the needle

    return ",posP"; // past the hay
}

/// formats placement key (part of the case category string)
std::string
SBufFindTest::placementKey() const
{
    // Ignore thePlacement because theBareNeedlePos covers it better: we may
    // try to place the needle somewhere, but hay limits the actual placement.

    // the placent does not matter if needle is not in hay
    if (theBareNeedlePos == std::string::npos)
        return std::string();

    if (theBareNeedlePos == 0)
        return "@B"; // at the beggining of the hay string
    if (theBareNeedlePos == theStringHay.length()-theStringNeedle.length())
        return "@E"; // at the end of the hay string
    return "@M"; // in the "middle" of the hay string
}

/// called when a test case fails; counts and possibly reports the failure
void
SBufFindTest::handleFailure(const char *method)
{
    // line break after "........." printed for previous tests
    if (!errorCount)
        std::cerr << std::endl;

    ++errorCount;

    if (errorCount > errorLimit) {
        std::cerr << "Will stop generating SBuf test cases because the " <<
                  "number of failed ones is over the limit: " << errorCount <<
                  " (after " << caseCount << " test cases)" << std::endl;
        CPPUNIT_ASSERT(errorCount <= errorLimit);
        /* NOTREACHED */
    }

    // format test case category; category allows us to hush failure reports
    // for already seen categories with failed cases (to reduce output noise)
    std::string category = "hay" + lengthKey(theStringHay) +
                           "." + method + '(';
    if (theReportQuote == '"')
        category += "needle" + lengthKey(theStringNeedle);
    else
        category += "char";
    category += placementKey();
    category += posKey();
    category += ')';

    if (hushSimilar) {
        if (failedCats.find(category) != failedCats.end())
            return; // do not report another similar test case failure
        failedCats.insert(category);
    }

    std::string reportPos = theReportPos;
    if (!reportPos.empty())
        reportPos = ", " + reportPos;

    std::cerr << "case" << caseCount << ": " <<
              "SBuf(\"" << theStringHay << "\")." << method <<
              "(" << theReportQuote << theReportNeedle << theReportQuote <<
              reportPos << ") returns " << PosToString(theFindSBuf) <<
              " instead of " << PosToString(theFindString) <<
              std::endl <<
              "    std::string(\""  << theStringHay << "\")." << method <<
              "(" << theReportQuote << theReportNeedle << theReportQuote <<
              reportPos << ") returns " << PosToString(theFindString) <<
              std::endl <<
              "    category: " << category << std::endl;

    ++reportCount;
}

/// generates a random string of the specified length
SBuf
SBufFindTest::RandomSBuf(const int length)
{
    static const char characters[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklomnpqrstuvwxyz";

    static std::mt19937 mt(time(0));

    // sizeof() counts the terminating zero at the end of characters
    // and the distribution is an 'inclusive' value range, so -2
    // TODO: add \0 character (needs reporting adjustments to print it as \0)
    static xuniform_int_distribution<uint8_t> dist(0, sizeof(characters)-2);

    SBuf buf;
    buf.reserveCapacity(length);
    for (int i = 0; i < length; ++i)
        buf.append(characters[dist(mt)]);
    return buf;
}

/// increments len to quickly cover [0, max] range, slowing down in risky areas
/// jumps to max+1 if caseLimit is reached
void
SBufFindTest::nextLen(SBuf::size_type &len, const SBuf::size_type max)
{
    assert(len <= max);

    if (caseCount >= caseLimit)
        len = max+1; // avoid future test cases
    else if (len <= 10)
        ++len; // move slowly at the beginning of the [0,max] range
    else if (len >= max - 10)
        ++len; // move slowly at the end of the [0,max] range
    else {
        // move fast in the middle of the [0,max] range
        len += len/10 + 1;

        // but do not overshoot the interesting area at the end of the range
        if (len > max - 10)
            len = max - 10;
    }
}

/// Places the needle into the hay using cleanHay as a starting point.
void
SBufFindTest::placeNeedle(const SBuf &cleanHay)
{
    // For simplicity, we do not overwrite clean hay characters but use them as
    // needle suffix and/or prefix. Should not matter since hay length varies?

    // TODO: support two needles per hay (explicitly)
    // TODO: better handle cases where clean hay already contains needle
    switch (thePlacement) {
    case placeBeginning:
        theSBufHay.assign(theSBufNeedle).append(cleanHay);
        break;

    case placeMiddle: {
        const SBuf firstHalf = cleanHay.substr(0, cleanHay.length()/2);
        const SBuf secondHalf = cleanHay.substr(cleanHay.length()/2);
        theSBufHay.assign(firstHalf).append(theSBufNeedle).append(secondHalf);
        break;
    }

    case placeEnd:
        theSBufHay.assign(cleanHay).append(theSBufNeedle);
        break;

    case placeNowhere:
        theSBufHay.assign(cleanHay);
        break;

    case placeEof:
        assert(false); // should not happen
        break;
    }
}

