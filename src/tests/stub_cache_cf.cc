/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration File Parsing */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/Gadgets.h"
#include "ConfigParser.h"
#include "wordlist.h"

#define STUB_API "cache_cf.cc"
#include "tests/STUB.h"

#include "cache_cf.h"
const char *cfg_directive = nullptr;
const char *cfg_filename = nullptr;
int config_lineno = 0;
char config_input_line[BUFSIZ] = {};
void self_destruct(void) STUB
void parse_int(int *) STUB
void parse_onoff(int *) STUB
void parse_eol(char *volatile *) STUB
void parse_wordlist(wordlist **) STUB
void requirePathnameExists(const char *, const char *) STUB_NOP
void parse_time_t(time_t *) STUB
void ConfigParser::ParseUShort(unsigned short *) STUB
void ConfigParser::ParseWordList(wordlist **) STUB
void parseBytesOptionValue(size_t *, const char *, char const *) STUB
void dump_acl_access(StoreEntry *, const char *, acl_access *) STUB
void dump_acl_list(StoreEntry*, ACLList*) STUB

