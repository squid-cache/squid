/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
#include "YesNoNone.h"

#define STUB_API "cache_cf.cc"
#include "tests/STUB.h"

void self_destruct(void) STUB
void parse_int(int *var) STUB
void parse_onoff(int *var) STUB
void parse_eol(char *volatile *var) STUB
void parse_wordlist(wordlist ** list) STUB
void requirePathnameExists(const char *name, const char *path) STUB_NOP
void parse_time_t(time_t * var) STUB
char * strtokFile(void) STUB_RETVAL(NULL)
void ConfigParser::ParseUShort(unsigned short *var) STUB
void dump_acl_access(StoreEntry * entry, const char *name, acl_access * head) STUB
void dump_acl_list(StoreEntry*, ACLList*) STUB
YesNoNone::operator void*() const { STUB_NOP; return NULL; }

