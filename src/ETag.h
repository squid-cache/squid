/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ETAG_H
#define SQUID_SRC_ETAG_H

/**
 * ETag support is rudimantal; this struct is likely to change
 * Note: "str" points to memory in HttpHeaderEntry (for now)
 *       so ETags should be used as tmp variables only (for now)
 */
class ETag
{
public:
    const char *str;            ///< quoted-string
    int weak;                   ///< true if it is a weak validator
};

/* ETag */
int etagParseInit(ETag *, const char *); //STUB_RETVAL(0)
/// whether etags are strong-equal
bool etagIsStrongEqual(const ETag &, const ETag &); //STUB_RETVAL(false)
/// whether etags are weak-equal
bool etagIsWeakEqual(const ETag &, const ETag &); //STUB_RETVAL(false)

#endif /* SQUID_SRC_ETAG_H */

