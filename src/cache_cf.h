/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration File Parsing */

#ifndef SQUID_SRC_CACHE_CF_H
#define SQUID_SRC_CACHE_CF_H

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
/// Parse bytes number from a string
void parseBytesOptionValue(size_t * bptr, const char *units, char const * value);

/// During parsing, the name of the current squid.conf directive being parsed.
extern const char *cfg_directive;
extern const char *cfg_filename;
extern int config_lineno;
extern char config_input_line[BUFSIZ];

#endif /* SQUID_SRC_CACHE_CF_H */

