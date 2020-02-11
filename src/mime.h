/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 25    MIME Parsing and Internal Icons */

#ifndef SQUID_MIME_H_
#define SQUID_MIME_H_

void mimeInit(char *filename);
const char *mimeGetContentEncoding(const char *fn);
const char *mimeGetContentType(const char *fn);
const char *mimeGetIconURL(const char *fn);
char mimeGetTransferMode(const char *fn);
bool mimeGetDownloadOption(const char *fn);
bool mimeGetViewOption(const char *fn);

#endif /* SQUID_MIME_H_ */

