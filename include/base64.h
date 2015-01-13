/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_BASE64_H
#define _SQUID_BASE64_H

#ifdef __cplusplus
extern "C" {
#endif

// Decoding functions

/// Calculate the decoded length of a given nul-terminated encoded string.
/// NULL pointer and empty strings are accepted, result is zero.
/// Any return value <= zero means no decoded result can be produced.
extern int base64_decode_len(const char *encodedData);

/// Decode a base-64 encoded blob into a provided buffer.
/// Will not terminate the resulting string.
/// In-place decoding overlap is supported if result is equal or earlier that the source pointer.
///
/// \return number of bytes filled in result.
extern int base64_decode(char *result, unsigned int result_max_size, const char *encoded);

// Encoding functions

/// Calculate the buffer size required to hold the encoded form of
/// a string of length 'decodedLen' including all terminator bytes.
extern int base64_encode_len(int decodedLen);

/// Base-64 encode a string into a given buffer.
/// Will not terminate the resulting string.
/// \return the number of bytes filled in result.
extern int base64_encode(char *result, int result_max_size, const char *data, int data_size);

/// Base-64 encode a string into a given buffer.
/// Will terminate the resulting string.
/// \return the number of bytes filled in result. Including the terminator.
extern int base64_encode_str(char *result, int result_max_size, const char *data, int data_size);

// Old encoder. Now a wrapper for the new. Takes a binary array of known length.
// Output is presented in a static buffer which will only remain valid until next call.
// Ensures a nul-terminated result. Will always return non-NULL.
extern const char *base64_encode_bin(const char *data, int len);

// Old encoder. Now a wrapper for the new.
// Output is presented in a static buffer which will only remain valid until next call.
// Ensures a nul-terminated result. Will always return non-NULL.
extern const char *old_base64_encode(const char *decoded);

#ifdef __cplusplus
}
#endif
#endif /* _SQUID_BASE64_H */

