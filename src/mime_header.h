/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 25    MiME Header Parsing */

#ifndef SQUID_MIME_HEADER_H_
#define SQUID_MIME_HEADER_H_

/**
 * Scan for the end of mime header block.
 *
 * Which is one of the following octet patterns:
 * - CRLF CRLF, or
 * - CRLF LF, or
 * - LF CRLF, or
 * - LF LF or,
 *   if mime header block is empty:
 * - LF or
 * - CRLF
 *
 * Also detects whether a obf-fold pattern exists within the mime block
 * - CR*LF (SP / HTAB)
 *
 * \param containsObsFold will be set to true if obs-fold pattern is found.
 */
size_t headersEnd(const char *, size_t, bool &containsObsFold);

inline size_t
headersEnd(const SBuf &buf, bool &containsObsFold)
{
    return headersEnd(buf.rawContent(), buf.length(), containsObsFold);
}

/// \deprecated caller needs to be fixed to handle obs-fold
inline size_t
headersEnd(const char *buf, size_t sz)
{
    bool ignored;
    return headersEnd(buf, sz, ignored);
}

#endif /* SQUID_MIME_HEADER_H_ */

