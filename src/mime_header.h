/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 25    MiME Header Parsing */

#ifndef SQUID_MIME_HEADER_H_
#define SQUID_MIME_HEADER_H_

char *mime_get_header(const char *mime, const char *header);
char *mime_get_header_field(const char *mime, const char *name, const char *prefix);
size_t headersEnd(const char *, size_t);

#endif /* SQUID_MIME_HEADER_H_ */

