/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/Uri.h"
#include "base/CharacterSet.h"
#include "Debug.h"
#include "tests/testURL.h"
#include "unitTestMain.h"

#include <chrono>
#include <cppunit/TestAssert.h>
#include <sstream>

CPPUNIT_TEST_SUITE_REGISTRATION( testURL );

/* init memory pools */

void
testURL::setUp()
{
    Mem::Init();
    AnyP::UriScheme::Init();
}

/*
 * we can construct a URL with a AnyP::UriScheme.
 * This creates a URL for that scheme.
 */
void
testURL::testConstructScheme()
{
    AnyP::UriScheme empty_scheme;
    AnyP::Uri protoless_url(AnyP::PROTO_NONE);
    CPPUNIT_ASSERT_EQUAL(empty_scheme, protoless_url.getScheme());

    AnyP::UriScheme ftp_scheme(AnyP::PROTO_FTP);
    AnyP::Uri ftp_url(AnyP::PROTO_FTP);
    CPPUNIT_ASSERT_EQUAL(ftp_scheme, ftp_url.getScheme());
}

/*
 * a default constructed URL has scheme "NONE".
 * Also, we should be able to use new and delete on
 * scheme instances.
 */
void
testURL::testDefaultConstructor()
{
    AnyP::UriScheme aScheme;
    AnyP::Uri aUrl;
    CPPUNIT_ASSERT_EQUAL(aScheme, aUrl.getScheme());

    auto *urlPointer = new AnyP::Uri;
    CPPUNIT_ASSERT(urlPointer != NULL);
    delete urlPointer;
}

void
testURL::benchmarkEncoder()
{
#if USE_BENCHMARKS
    typedef std::chrono::high_resolution_clock Clock;

    const auto delta = [](const std::chrono::nanoseconds &value) -> double {
        return static_cast<double>(std::chrono::nanoseconds(value).count())/1000000;
    };

    const int testLength = 2<<15;
    const CharacterSet charX("xX","xX");
    const CharacterSet charA("aA","aA");
    SBuf result;
    result.reserveSpace(testLength);

    std::cout << "Benchmark setup ";
    SBuf inputA("a");
    inputA.reserveSpace(testLength);
    for (int i = 0; i < 15; ++i) {
        inputA.append(inputA);
    }

    std::cout << std::endl << "AnyP::Uri::Encode non-change: ";
    std::cout.flush();
    auto start = Clock::now();
    for (const auto ch : inputA) {
        if (charA[ch])
            result.appendf("%%%02X", static_cast<unsigned int>(ch));
        else
            result.append(ch);
    }
    auto end = Clock::now();
    std::cout << "baseline= " << delta(end-start);
    std::cout.flush();

    start = Clock::now();
    (void)AnyP::Uri::Encode(inputA, charA);
    end = Clock::now();
    std::cout << " , encoder= " << delta(end-start) << std::endl;
    std::cout.flush();

    std::cout << "AnyP::Uri::Encode all changed: ";
    std::cout.flush();
    start = Clock::now();
    for (const auto ch : inputA) {
        if (charX[ch])
            result.appendf("%%%02X", static_cast<unsigned int>(ch));
        else
            result.append(ch);
    }
    end = Clock::now();
    std::cout << "baseline= " << delta(end-start);
    std::cout.flush();

    start = Clock::now();
    (void)AnyP::Uri::Encode(inputA, charX);
    end = Clock::now();
    std::cout << " , encoder= " << delta(end-start) << std::endl;
    std::cout.flush();
#endif
}

