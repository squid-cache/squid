/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration File Parsing */

#ifndef SQUID_CACHE_CF_H_
#define SQUID_CACHE_CF_H_

class wordlist;

void configFreeMemory(void);
void self_destruct(void);
void add_http_port(char *portspec);

/* extra functions from cache_cf.c useful for lib modules */
void parse_int(int *var);
void parse_onoff(int *var);
void parse_eol(char *volatile *var);
void parse_wordlist(wordlist ** list);
void requirePathnameExists(const char *name, const char *path);
void parse_time_t(time_t * var);

#endif /* SQUID_CACHE_CF_H_ */

