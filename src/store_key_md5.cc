#include "squid.h"

const char *
storeKeyText(const unsigned char *key)
{
    LOCAL_ARRAY(char, buf, 33);
    int i;
    int o;
    for (i = 0; i < MD5_DIGEST_CHARS; i++) {
	o = i << 1;
	snprintf(buf + o, 33 - o, "%02X", *(key + i));
    }
    return buf;
}

const unsigned char *
storeKeyScan(const char *buf)
{
    static unsigned char digest[MD5_DIGEST_CHARS];
    int i;
    int j = 0;
    unsigned char t[3];
    for (i = 0; i < MD5_DIGEST_CHARS; i++) {
	t[0] = *(buf + (j++));
	t[1] = *(buf + (j++));
	t[2] = '\0';
	*(digest + i) = (unsigned char) strtol(t, NULL, 16);
    }
    return digest;
}

int
storeKeyHashCmp(const void *a, const void *b)
{
    const unsigned char *A = a;
    const unsigned char *B = b;
    int i;
    for (i = 0; i < MD5_DIGEST_CHARS; i++) {
	if (A[i] < B[i])
	    return -1;
	if (A[i] > B[i])
	    return 1;
    }
    return 0;
}

unsigned int
storeKeyHashHash(const void *key, unsigned int n)
{
    /* note, n must be a power of 2! */
    const unsigned char *digest = key;
    unsigned int i = digest[0]
    | digest[1] << 8
    | digest[2] << 16
    | digest[3] << 24;
    return (i & (--n));
}

const cache_key *
storeKeyPrivate(const char *url, method_t method, int num)
{
    static cache_key digest[MD5_DIGEST_CHARS];
    MD5_CTX M;
    int n;
    char key_buf[MAX_URL + 100];
    assert(num > 0);
    debug(20, 3) ("storeKeyPrivate: '%s'\n", url);
    n = snprintf(key_buf, MAX_URL + 100, "%d %s %s",
	num,
	RequestMethodStr[method],
	url);
    MD5Init(&M);
    MD5Update(&M, key_buf, n);
    MD5Final(digest, &M);
    return digest;
}

const cache_key *
storeKeyPublic(const char *url, method_t method)
{
    static cache_key digest[MD5_DIGEST_CHARS];
    MD5_CTX M;
    int n;
    char key_buf[MAX_URL + 100];
    n = snprintf(key_buf, MAX_URL + 100, "%s %s",
	RequestMethodStr[method],
	url);
    MD5Init(&M);
    MD5Update(&M, key_buf, n);
    MD5Final(digest, &M);
    return digest;
}

const cache_key *
storeKeyDup(const cache_key * key)
{
    cache_key *dup = xmalloc(MD5_DIGEST_CHARS);
    xmemcpy(dup, key, MD5_DIGEST_CHARS);
    meta_data.store_keys += MD5_DIGEST_CHARS;
    return dup;
}

void
storeKeyFree(const cache_key * key)
{
    xfree((void *) key);
    meta_data.store_keys -= MD5_DIGEST_CHARS;
}

int
storeKeyHashBuckets(int nobj)
{
    if (nobj < 0x2000)
	return 0x2000;
    if (nobj < 0x4000)
	return 0x4000;
    if (nobj < 0x8000)
	return 0x8000;
    return 0x10000;
}
