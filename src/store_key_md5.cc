#include "squid.h"

static cache_key null_key[MD5_DIGEST_CHARS];

const char *
storeKeyText(const unsigned char *key)
{
    static MemBuf mb = MemBufNULL;
    int i;
    memBufReset(&mb);
    for (i = 0; i < MD5_DIGEST_CHARS; i++)
	memBufPrintf(&mb, "%02X", *(key + i));
    return mb.buf;
}

const unsigned char *
storeKeyScan(const char *buf)
{
    static unsigned char digest[MD5_DIGEST_CHARS];
    int i;
    int j = 0;
    char t[3];
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
    debug(20, 3) ("storeKeyPrivate: %s %s\n",
	RequestMethodStr[method], url);
    n = snprintf(key_buf, sizeof(key_buf), "%d %s %s",
	num,
	RequestMethodStr[method],
	url);
    MD5Init(&M);
    MD5Update(&M, (unsigned char *) key_buf, n);
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
    n = snprintf(key_buf, sizeof(key_buf), "%s %s",
	RequestMethodStr[method],
	url);
    MD5Init(&M);
    MD5Update(&M, (unsigned char *) key_buf, n);
    MD5Final(digest, &M);
    return digest;
}

const cache_key *
storeKeyDup(const cache_key * key)
{
    cache_key *dup = xmalloc(MD5_DIGEST_CHARS);
    xmemcpy(dup, key, MD5_DIGEST_CHARS);
    /* XXX account key */
    return dup;
}

void
storeKeyFree(const cache_key * key)
{
    xfree((void *) key);
    /* XXX account key */
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

int
storeKeyNull(const cache_key * key)
{
    if (memcmp(key, null_key, MD5_DIGEST_CHARS) == 0)
	return 1;
    else
	return 0;
}

void
storeKeyInit(void)
{
    memset(null_key, '\0', MD5_DIGEST_CHARS);
}
