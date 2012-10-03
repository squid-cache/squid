/*
 * DEBUG: section 03    Configuration File Parsing
 * AUTHOR: Robert Collins
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

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
YesNoNone::operator void*() const { STUB_NOP; return NULL; }
