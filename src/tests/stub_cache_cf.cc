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
#include "ConfigParser.h"
#include "wordlist.h"

#define STUB_API "cache_cf.cc"
#include "tests/STUB.h"

#include "cache_cf.h"
void self_destruct(void) STUB
void parse_int(int *var) STUB
void parse_onoff(int *var) STUB
void parse_eol(char *volatile *var) STUB
void parse_wordlist(wordlist ** list) STUB
void requirePathnameExists(const char *name, const char *path) STUB_NOP
void parse_time_t(time_t * var) STUB
void ConfigParser::ParseUShort(unsigned short *var) STUB
void ConfigParser::ParseWordList(wordlist **) STUB
void dump_acl_access(StoreEntry * entry, const char *name, acl_access * head) STUB
void dump_acl_list(StoreEntry*, ACLList*) STUB

