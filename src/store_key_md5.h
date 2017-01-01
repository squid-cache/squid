/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager MD5 Cache Keys */

#ifndef SQUID_STORE_KEY_MD5_H_
#define SQUID_STORE_KEY_MD5_H_

#include "hash.h"
#include "typedefs.h"

class HttpRequestMethod;
class HttpRequest;

typedef enum {
    ksDefault,
    ksRevalidation
} KeyScope;

cache_key *storeKeyDup(const cache_key *);
cache_key *storeKeyCopy(cache_key *, const cache_key *);
void storeKeyFree(const cache_key *);
const cache_key *storeKeyScan(const char *);
const char *storeKeyText(const cache_key *);
const cache_key *storeKeyPublic(const char *, const HttpRequestMethod&, const KeyScope keyScope = ksDefault);
const cache_key *storeKeyPublicByRequest(HttpRequest *, const KeyScope keyScope = ksDefault);
const cache_key *storeKeyPublicByRequestMethod(HttpRequest *, const HttpRequestMethod&, const KeyScope keyScope = ksDefault);
const cache_key *storeKeyPrivate(const char *, const HttpRequestMethod&, int);
int storeKeyHashBuckets(int);
int storeKeyNull(const cache_key *);
void storeKeyInit(void);

extern HASHHASH storeKeyHashHash;
extern HASHCMP storeKeyHashCmp;

#endif /* SQUID_STORE_KEY_MD5_H_ */

