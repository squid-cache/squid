/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "ETag.h"
#include "unitTestMain.h"

#include <cstring>

/*
 * Unit tests for the ETag class which handles HTTP entity tag parsing
 * and comparison as defined in RFC 7232.
 */

class TestETag : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestETag);
    CPPUNIT_TEST(testParseStrongETag);
    CPPUNIT_TEST(testParseWeakETag);
    CPPUNIT_TEST(testParseInvalidETag);
    CPPUNIT_TEST(testStrongEqualityMatching);
    CPPUNIT_TEST(testStrongEqualityNonMatching);
    CPPUNIT_TEST(testStrongEqualityWithWeakTags);
    CPPUNIT_TEST(testWeakEqualityMatching);
    CPPUNIT_TEST(testWeakEqualityNonMatching);
    CPPUNIT_TEST(testWeakEqualityMixedStrength);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testParseStrongETag();
    void testParseWeakETag();
    void testParseInvalidETag();
    void testStrongEqualityMatching();
    void testStrongEqualityNonMatching();
    void testStrongEqualityWithWeakTags();
    void testWeakEqualityMatching();
    void testWeakEqualityNonMatching();
    void testWeakEqualityMixedStrength();
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestETag);

void
TestETag::testParseStrongETag()
{
    ETag etag;
    const char *strongTag = "\"strong-etag-value\"";
    
    auto result = etagParseInit(&etag, strongTag);
    
    CPPUNIT_ASSERT_EQUAL(1, result);
    CPPUNIT_ASSERT(etag.str != nullptr);
    CPPUNIT_ASSERT_EQUAL(0, etag.weak);
    CPPUNIT_ASSERT_EQUAL(0, strcmp(etag.str, strongTag));
}

void
TestETag::testParseWeakETag()
{
    ETag etag;
    const char *weakTag = "W/\"weak-etag-value\"";
    
    auto result = etagParseInit(&etag, weakTag);
    
    CPPUNIT_ASSERT_EQUAL(1, result);
    CPPUNIT_ASSERT(etag.str != nullptr);
    CPPUNIT_ASSERT_EQUAL(1, etag.weak);
    // str should point to the quoted part after "W/"
    CPPUNIT_ASSERT_EQUAL(0, strcmp(etag.str, "\"weak-etag-value\""));
}

void
TestETag::testParseInvalidETag()
{
    ETag etag;
    
    // Missing quotes
    int result1 = etagParseInit(&etag, "no-quotes");
    CPPUNIT_ASSERT_EQUAL(0, result1);
    CPPUNIT_ASSERT(etag.str == nullptr);
    
    // Only opening quote
    int result2 = etagParseInit(&etag, "\"missing-end");
    CPPUNIT_ASSERT_EQUAL(0, result2);
    CPPUNIT_ASSERT(etag.str == nullptr);
    
    // Only closing quote
    int result3 = etagParseInit(&etag, "missing-start\"");
    CPPUNIT_ASSERT_EQUAL(0, result3);
    CPPUNIT_ASSERT(etag.str == nullptr);
    
    // Empty string
    int result4 = etagParseInit(&etag, "");
    CPPUNIT_ASSERT_EQUAL(0, result4);
    CPPUNIT_ASSERT(etag.str == nullptr);
    
    // Single quote
    int result5 = etagParseInit(&etag, "\"");
    CPPUNIT_ASSERT_EQUAL(0, result5);
    CPPUNIT_ASSERT(etag.str == nullptr);
}

void
TestETag::testStrongEqualityMatching()
{
    ETag tag1, tag2;
    const char *strongTag1 = "\"matching-value\"";
    const char *strongTag2 = "\"matching-value\"";
    
    etagParseInit(&tag1, strongTag1);
    etagParseInit(&tag2, strongTag2);
    
    // Both are strong ETags with matching values
    CPPUNIT_ASSERT(etagIsStrongEqual(tag1, tag2));
}

void
TestETag::testStrongEqualityNonMatching()
{
    ETag tag1, tag2;
    const char *strongTag1 = "\"value-one\"";
    const char *strongTag2 = "\"value-two\"";
    
    etagParseInit(&tag1, strongTag1);
    etagParseInit(&tag2, strongTag2);
    
    // Both are strong but values don't match
    CPPUNIT_ASSERT(!etagIsStrongEqual(tag1, tag2));
}

void
TestETag::testStrongEqualityWithWeakTags()
{
    ETag strongTag, weakTag1, weakTag2;
    const char *strong = "\"same-value\"";
    const char *weak1 = "W/\"same-value\"";
    const char *weak2 = "W/\"same-value\"";
    
    etagParseInit(&strongTag, strong);
    etagParseInit(&weakTag1, weak1);
    etagParseInit(&weakTag2, weak2);
    
    // Strong equality requires BOTH tags to be strong
    CPPUNIT_ASSERT(!etagIsStrongEqual(strongTag, weakTag1));
    CPPUNIT_ASSERT(!etagIsStrongEqual(weakTag1, strongTag));
    CPPUNIT_ASSERT(!etagIsStrongEqual(weakTag1, weakTag2));
}

void
TestETag::testWeakEqualityMatching()
{
    ETag tag1, tag2;
    const char *tag1Str = "\"matching-value\"";
    const char *tag2Str = "\"matching-value\"";
    
    etagParseInit(&tag1, tag1Str);
    etagParseInit(&tag2, tag2Str);
    
    // Weak equality just checks if the opaque-tags match
    CPPUNIT_ASSERT(etagIsWeakEqual(tag1, tag2));
}

void
TestETag::testWeakEqualityNonMatching()
{
    ETag tag1, tag2;
    const char *tag1Str = "\"different-value-1\"";
    const char *tag2Str = "\"different-value-2\"";
    
    etagParseInit(&tag1, tag1Str);
    etagParseInit(&tag2, tag2Str);
    
    CPPUNIT_ASSERT(!etagIsWeakEqual(tag1, tag2));
}

void
TestETag::testWeakEqualityMixedStrength()
{
    ETag strongTag, weakTag;
    const char *strong = "\"same-value\"";
    const char *weak = "W/\"same-value\"";
    
    etagParseInit(&strongTag, strong);
    etagParseInit(&weakTag, weak);
    
    // Weak equality should match regardless of weak/strong distinction
    CPPUNIT_ASSERT(etagIsWeakEqual(strongTag, weakTag));
    CPPUNIT_ASSERT(etagIsWeakEqual(weakTag, strongTag));
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
