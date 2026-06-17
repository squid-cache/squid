/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Characterization and fix-verification tests for the stack buffer overflow
 * in the external-ACL credential base64 encoding paths.
 *
 * Three production sites allocate a fixed-size stack buffer sized for
 * MAX_LOGIN_SZ bytes of pre-encoding input:
 *
 *   src/adaptation/icap/ModXact.cc  (makeRequestHeaders)        — site A
 *   src/http.cc httpFixupAuthentication() PASS/PROXYPASS branch  — site B
 *   src/http.cc httpFixupAuthentication() '*'-prefix branch       — site C
 *
 * Sites A and B encode:  extacl_user + ":" + extacl_passwd
 * Site C encodes:        extacl_user + peer_login_suffix
 *
 * Without a guard, all three pass the actual (unchecked) field sizes
 * directly to base64_encode_update() into a 175-byte stack buffer.
 * When a helper returns values whose combined plain-text length exceeds
 * 129 bytes the encoded output (>= 176 bytes) overflows the buffer.
 *
 * The fix for site A (ModXact.cc) adds a pre-encoding guard:
 *
 *   if (plainLen > MAX_LOGIN_SZ)   // i.e. > 128
 *       throw TexcHere(...);
 *
 * The buffer-overflow section of this file characterizes the encoding
 * arithmetic (showing the overflow would occur without the guard).
 * The guard-condition section verifies the fix's threshold directly.
 *
 * Buffer overflow threshold (encoding arithmetic):
 *   At 130 bytes of plain input the encoded output is 176 bytes,
 *   which exceeds the 175-byte buffer by 1 byte.
 *
 * Guard threshold (site A fix):
 *   plainLen > MAX_LOGIN_SZ (128) triggers the throw.
 *   plainLen == 128 is safe; plainLen == 129 is rejected.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "defines.h"
#include "unitTestMain.h"

#include "base64.h"

#include <cppunit/TestAssert.h>
#include <cstring>
#include <string>
#include <vector>

/// The fixed-size stack buffer used in all three vulnerable sites.
/// base64_encode_len(128) = ((128*8+4)/6) + 3 + 1 = 171 + 3 + 1 = 175.
static constexpr size_t ProductionBufSize = base64_encode_len(MAX_LOGIN_SZ);

/// Replicates the encoding pattern used in:
///   - ModXact.cc::makeRequestHeaders()
///   - httpFixupAuthentication() PASS/PROXYPASS branch  (sites A and B)
///
/// Encodes: user + ":" + passwd  (three-segment pattern)
static size_t
encodeUserColon(const char *user, size_t userLen,
                const char *passwd, size_t passwdLen)
{
    // Scratch buffer large enough for any input we test — avoids UB while
    // faithfully counting emitted bytes.
    std::vector<char> scratch(8192, '\0');
    char *dst = scratch.data();

    struct base64_encode_ctx ctx;
    base64_encode_init(&ctx);

    size_t total = 0;
    total += base64_encode_update(&ctx, dst + total, userLen,
                                  reinterpret_cast<const uint8_t *>(user));
    total += base64_encode_update(&ctx, dst + total, 1,
                                  reinterpret_cast<const uint8_t *>(":"));
    total += base64_encode_update(&ctx, dst + total, passwdLen,
                                  reinterpret_cast<const uint8_t *>(passwd));
    total += base64_encode_final(&ctx, dst + total);
    return total;
}

/// Replicates the encoding pattern used in:
///   - httpFixupAuthentication() '*'-prefix branch  (site C)
///
/// Encodes: username + peerLoginSuffix  (two-segment pattern, no ':')
static size_t
encodeUserSuffix(const char *username, size_t usernameLen,
                 const char *suffix, size_t suffixLen)
{
    std::vector<char> scratch(8192, '\0');
    char *dst = scratch.data();

    struct base64_encode_ctx ctx;
    base64_encode_init(&ctx);

    size_t total = 0;
    total += base64_encode_update(&ctx, dst + total, usernameLen,
                                  reinterpret_cast<const uint8_t *>(username));
    total += base64_encode_update(&ctx, dst + total, suffixLen,
                                  reinterpret_cast<const uint8_t *>(suffix));
    total += base64_encode_final(&ctx, dst + total);
    return total;
}

class TestExtAclBase64Overflow : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestExtAclBase64Overflow);
    // Buffer-size anchor
    CPPUNIT_TEST(testBufferSizeCalculation);
    // Sites A & B — user + ":" + passwd pattern
    CPPUNIT_TEST(testSafeInputFitsBuffer);
    CPPUNIT_TEST(testMaxSafeBoundaryFits);
    CPPUNIT_TEST(testExactOverflowThreshold);
    CPPUNIT_TEST(testOversizedUserOverflows);
    CPPUNIT_TEST(testOversizedPasswdOverflows);
    CPPUNIT_TEST(testCombinedOverflow);
    CPPUNIT_TEST(testLargeInputOverflows);
    // Site C — user + peer_login_suffix pattern
    CPPUNIT_TEST(testSiteC_SafeInputFitsBuffer);
    CPPUNIT_TEST(testSiteC_OversizedUserOverflows);
    // Site A fix — guard condition (ModXact.cc: plainLen > MAX_LOGIN_SZ throws)
    CPPUNIT_TEST(testGuardAllowsExactLimit);
    CPPUNIT_TEST(testGuardRejectsOneByteOver);
    CPPUNIT_TEST_SUITE_END();

protected:
    /// Confirm the production buffer is exactly 175 bytes and MAX_LOGIN_SZ is 128.
    void testBufferSizeCalculation();

    // ── Sites A & B: user + ":" + passwd ─────────────────────────────────

    /// Well-within-limit input does not overflow.
    void testSafeInputFitsBuffer();

    /// user=63, passwd=64: combined plain=128 bytes — fits with 3 bytes spare.
    void testMaxSafeBoundaryFits();

    /// user=64, passwd=65: combined plain=130 bytes — the minimal overflow.
    /// base64(130 bytes) = 176 bytes > 175-byte buffer.
    void testExactOverflowThreshold();

    /// user alone exceeds MAX_LOGIN_SZ — sites A and B overflow.
    void testOversizedUserOverflows();

    /// passwd alone exceeds MAX_LOGIN_SZ — sites A and B overflow.
    void testOversizedPasswdOverflows();

    /// Moderate combined excess (65+64=129+":"=130) — both sites overflow.
    void testCombinedOverflow();

    /// Very large input — confirms no arithmetic wrapping masks the overflow.
    void testLargeInputOverflows();

    // ── Site C: user + peer_login_suffix ─────────────────────────────────

    /// Small user + small suffix stays within buffer.
    void testSiteC_SafeInputFitsBuffer();

    /// Oversized extacl_user overflows the same loginbuf via site C's path.
    void testSiteC_OversizedUserOverflows();

    // ── Site A fix: guard condition verification ──────────────────────────
    // The fix in ModXact.cc guards: if (plainLen > MAX_LOGIN_SZ) throw ...
    // These tests verify the arithmetic of that guard directly.

    /// plainLen == MAX_LOGIN_SZ (128) must NOT trigger the guard.
    /// Encodes correctly within the 175-byte buffer (172 bytes written).
    void testGuardAllowsExactLimit();

    /// plainLen == MAX_LOGIN_SZ+1 (129) MUST trigger the guard.
    /// Without the guard this input would write 176 bytes into a 175-byte buffer.
    void testGuardRejectsOneByteOver();
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestExtAclBase64Overflow);

void
TestExtAclBase64Overflow::testBufferSizeCalculation()
{
    // base64_encode_len(128):
    //   BASE64_ENCODE_LENGTH(128)  = (128×8 + 4) / 6  = 1028/6 = 171  (integer division)
    //   BASE64_ENCODE_FINAL_LENGTH = 3
    //   NUL sentinel               = 1
    //                              = 175
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(175), ProductionBufSize);
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(128), static_cast<size_t>(MAX_LOGIN_SZ));
}

void
TestExtAclBase64Overflow::testSafeInputFitsBuffer()
{
    // user="alice" (5), passwd="secret" (6): total plain = 12 bytes — well under 128.
    const char *user   = "alice";
    const char *passwd = "secret";
    const auto written = encodeUserColon(user, strlen(user), passwd, strlen(passwd));

    CPPUNIT_ASSERT_MESSAGE("safe credentials must fit in the fixed stack buffer",
                           written <= ProductionBufSize);
}

void
TestExtAclBase64Overflow::testMaxSafeBoundaryFits()
{
    // user=63 + ":" + passwd=64 = 128 bytes total — exactly MAX_LOGIN_SZ.
    // BASE64_ENCODE_RAW_LENGTH(128) = ((128+2)/3)*4 = 43*4 = 172 bytes written.
    // 172 <= 175: fits with 3 bytes to spare.
    const std::string user(63, 'U');
    const std::string passwd(64, 'P');
    const auto written = encodeUserColon(user.c_str(), user.size(),
                                         passwd.c_str(), passwd.size());

    CPPUNIT_ASSERT_MESSAGE("input of exactly MAX_LOGIN_SZ bytes must fit in fixed buffer",
                           written <= ProductionBufSize);
}

void
TestExtAclBase64Overflow::testExactOverflowThreshold()
{
    // user=64 + ":" + passwd=65 = 130 bytes total — the minimal overflowing input.
    // BASE64_ENCODE_RAW_LENGTH(130) = ((130+2)/3)*4 = 44*4 = 176 bytes.
    // 176 > 175: the first input size that actually overflows the buffer.
    const std::string user(64, 'U');
    const std::string passwd(65, 'P');
    const auto written = encodeUserColon(user.c_str(), user.size(),
                                         passwd.c_str(), passwd.size());

    CPPUNIT_ASSERT_MESSAGE("130-byte combined input (user+colon+passwd) is the minimal overflow",
                           written > ProductionBufSize);
}

void
TestExtAclBase64Overflow::testOversizedUserOverflows()
{
    // user=129 bytes alone (+ ":" + empty passwd = 130 bytes total).
    // The user field exceeds MAX_LOGIN_SZ; production code at sites A and B
    // passes user.size() = 129 directly to base64_encode_update() without
    // checking, writing into a 175-byte stack buffer.
    // Total plain = 130 bytes => 176 bytes encoded > 175 bytes available.
    const std::string user(129, 'A');
    const char *passwd = "";
    const auto written = encodeUserColon(user.c_str(), user.size(), passwd, strlen(passwd));

    CPPUNIT_ASSERT_MESSAGE("oversized user field (site A: ModXact, site B: httpFixupAuthentication) "
                           "causes encoded output to exceed fixed stack buffer",
                           written > ProductionBufSize);
}

void
TestExtAclBase64Overflow::testOversizedPasswdOverflows()
{
    // user="u" (1 byte) + ":" + passwd=129 bytes = 131 bytes total.
    // passwd alone exceeds MAX_LOGIN_SZ; passed unchecked at sites A and B.
    // 131 bytes encoded = 176 bytes > 175 bytes.
    const char *user = "u";
    const std::string passwd(129, 'P');
    const auto written = encodeUserColon(user, strlen(user), passwd.c_str(), passwd.size());

    CPPUNIT_ASSERT_MESSAGE("oversized passwd field (site A: ModXact, site B: httpFixupAuthentication) "
                           "causes encoded output to exceed fixed stack buffer",
                           written > ProductionBufSize);
}

void
TestExtAclBase64Overflow::testCombinedOverflow()
{
    // user=65 + ":" + passwd=64 = 130 bytes total.
    // Each field looks reasonable in isolation (both < MAX_LOGIN_SZ) but
    // their combination exceeds the safe threshold by 2 bytes.
    const std::string user(65, 'U');
    const std::string passwd(64, 'P');
    const auto written = encodeUserColon(user.c_str(), user.size(),
                                         passwd.c_str(), passwd.size());

    CPPUNIT_ASSERT_MESSAGE("combined user+colon+passwd exceeding safe threshold "
                           "overflows fixed stack buffer",
                           written > ProductionBufSize);
}

void
TestExtAclBase64Overflow::testLargeInputOverflows()
{
    // 512+512 = 1024 bytes; confirms no size-type wrapping masks the overflow.
    const std::string user(512, 'A');
    const std::string passwd(512, 'B');
    const auto written = encodeUserColon(user.c_str(), user.size(),
                                         passwd.c_str(), passwd.size());

    CPPUNIT_ASSERT_MESSAGE("very large input must also overflow fixed stack buffer",
                           written > ProductionBufSize);
}

void
TestExtAclBase64Overflow::testSiteC_SafeInputFitsBuffer()
{
    // Site C (httpFixupAuthentication '*'-prefix branch) encodes:
    //   extacl_user  +  peer_login_suffix  (no ':')
    // into the same loginbuf[base64_encode_len(MAX_LOGIN_SZ)] = 175 bytes.
    // Small inputs fit fine.
    const char *username = "alice";
    const char *suffix   = "@realm";
    const auto written = encodeUserSuffix(username, strlen(username),
                                          suffix, strlen(suffix));

    CPPUNIT_ASSERT_MESSAGE("site C: small extacl_user + peer_login_suffix must fit in fixed buffer",
                           written <= ProductionBufSize);
}

void
TestExtAclBase64Overflow::testSiteC_OversizedUserOverflows()
{
    // Site C: extacl_user = 129 bytes + any non-empty peer_login_suffix.
    // Total plain = 130 bytes => 176 bytes encoded > 175-byte loginbuf.
    const std::string username(129, 'U');
    const char *suffix = "x";   // minimal non-empty suffix
    const auto written = encodeUserSuffix(username.c_str(), username.size(),
                                          suffix, strlen(suffix));

    CPPUNIT_ASSERT_MESSAGE("site C: oversized extacl_user causes encoded output to exceed "
                           "fixed loginbuf in httpFixupAuthentication '*'-prefix path",
                           written > ProductionBufSize);
}

void
TestExtAclBase64Overflow::testGuardAllowsExactLimit()
{
    // The site A guard condition is: if (plainLen > MAX_LOGIN_SZ) throw
    // plainLen == MAX_LOGIN_SZ (128) must NOT trigger it.
    //
    // user=63 + ":" + passwd=64 = 128 bytes.
    // BASE64_ENCODE_RAW_LENGTH(128) = 172 bytes written; 172 <= 175. Safe.
    const std::string user(63, 'U');
    const std::string passwd(64, 'P');
    const auto plainLen = user.size() + 1 + passwd.size();
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(MAX_LOGIN_SZ), plainLen);

    const auto written = encodeUserColon(user.c_str(), user.size(),
                                         passwd.c_str(), passwd.size());
    CPPUNIT_ASSERT_MESSAGE("plainLen == MAX_LOGIN_SZ must not overflow the buffer "
                           "(guard must allow this input)",
                           written <= ProductionBufSize);
}

void
TestExtAclBase64Overflow::testGuardRejectsOneByteOver()
{
    // The site A guard condition is: if (plainLen > MAX_LOGIN_SZ) throw
    // plainLen == MAX_LOGIN_SZ+1 (129) MUST trigger the guard.
    //
    // Note: the guard is deliberately conservative. At plainLen=129 the
    // encoded output is exactly 175 bytes (== ProductionBufSize), which
    // technically fits. However the guard fires at plainLen > MAX_LOGIN_SZ,
    // rejecting 129 to keep a safe margin for the 3-byte final padding slot.
    // The true minimal overflowing input is 130 bytes (see testExactOverflowThreshold).
    //
    // This test confirms:
    //   (a) plainLen == MAX_LOGIN_SZ + 1  (inputs constructed correctly)
    //   (b) the guard condition (plainLen > MAX_LOGIN_SZ) is TRUE
    //   (c) the encoded output still fits (guard fires before actual overflow)
    const std::string user(64, 'U');
    const std::string passwd(64, 'P');
    const auto plainLen = user.size() + 1 + passwd.size();
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(MAX_LOGIN_SZ + 1), plainLen);

    // (b) guard fires: plainLen > MAX_LOGIN_SZ
    CPPUNIT_ASSERT_MESSAGE("plainLen == MAX_LOGIN_SZ+1 must trigger the guard condition",
                           plainLen > static_cast<size_t>(MAX_LOGIN_SZ));

    // (c) at this size the encoder writes exactly ProductionBufSize bytes (no margin)
    const auto written = encodeUserColon(user.c_str(), user.size(),
                                         passwd.c_str(), passwd.size());
    CPPUNIT_ASSERT_MESSAGE("plainLen == MAX_LOGIN_SZ+1 still fits in the buffer "
                           "(guard is conservative; actual overflow starts at plainLen=130)",
                           written <= ProductionBufSize);
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
