/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration File Parsing */

#ifndef SQUID_PARSING_H
#define SQUID_PARSING_H

#include "ip/Address.h"

double xatof(const char *token);
int xatoi(const char *token);
unsigned int xatoui(const char *token, char eov = '\0');
long xatol(const char *token);
int64_t xatoll(const char *token, int base, char eov = '\0');
unsigned short xatos(const char *token);

/**
 * Parse a 64-bit integer value.
 */
int64_t GetInteger64(void);

/**
 * Parses an integer value.
 * Uses a method that obeys hexadecimal 0xN syntax needed for certain bitmasks.
 * self_destruct() will be called to abort when invalid tokens are encountered.
 */
int GetInteger(void);

/**
 * Parse a percentage value, e.g., 20%.
 * The behavior of this function is similar as GetInteger().
 * The difference is that the token might contain '%' as percentage symbol (%),
 * and we may further check whether the value is in the range of [0, 100].
 * For example, 20% and 20 are both valid tokens, while 101%, 101, -1 are invalid.
 *
 * \param limit whether to check the value is within 0-100% limit
 *
 * \return the percentage as a decimal number. ie 100% = 1.00, 50% = 0.5
 */
double GetPercentage(bool limit = true);

unsigned short GetShort(void);

// on success, returns true and sets *p (if any) to the end of the integer
bool StringToInt(const char *str, int &result, const char **p, int base);
bool StringToInt64(const char *str, int64_t &result, const char **p, int base);

/**
 * Parse a socket address (host:port), fill the given Ip::Address object
 * \retval false     Failure.
 * \retval true      Success.
 * Destroys token during parse.
 */
bool GetHostWithPort(char *token, Ip::Address *ipa);

#endif /* SQUID_PARSING_H */

