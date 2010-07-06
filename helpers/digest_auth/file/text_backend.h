/*
 * text_backend.h
 *
 * AUTHOR: Robert Collins.
 *
 * Example digest authentication backend for Squid,
 *
 * - comment lines are possible and should start with a '#';
 * - empty or blank lines are possible;
 * - file format is username:password
 *
 * This implementation could be improved by using such a triple for
 * the file format.  However storing such a triple does little to
 * improve security: If compromised the username:realm:HA1 combination
 * is "plaintext equivalent" - for the purposes of digest authentication
 * they allow the user access. Password syncronisation is not tackled
 * by digest - just preventing on the wire compromise.
 *
 * Copyright (c) 2003  Robert Collins  <robertc@squid-cache.org>
 */

#include "digest_common.h"

extern void TextArguments(int argc, char **argv);
extern void TextHHA1(RequestData * requestData);
