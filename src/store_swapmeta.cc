#include "squid.h"

#define squid_key_size MD5_DIGEST_CHARS

/* build swapfile header */
int
storeBuildMetaData(StoreEntry * e, char *swap_buf_c)
{
    MemObject *mem;
    int keylength;
    int a = STORE_META_TLD_START;
    char *meta_buf;
    mem = e->mem_obj;
    meta_buf = mem->swapout.meta_buf;
    debug(20, 3) ("storeBuildSwapFileHeader: called.\n");
    assert(e->swap_status == SWAPOUT_WRITING);
    if (!meta_buf)
	meta_buf = mem->swapout.meta_buf = xmalloc(1024);
    /* construct header */
    /* add Length(int)-Type(char)-Data encoded info  */
    if (squid_key_size < 0)
	keylength = strlen(e->key);
    else
	keylength = squid_key_size;
    meta_buf[0] = META_OK;
    xmemcpy(&meta_buf[1], &a, sizeof(int));
    mem->swapout.meta_len = STORE_META_TLD_START;
    addSwapHdr(STORE_META_KEY, keylength, (void *) e->key,
	mem->swapout.meta_buf, &mem->swapout.meta_len);
    addSwapHdr(STORE_META_STD, STORE_HDR_METASIZE, (void *) &e->timestamp,
	mem->swapout.meta_buf, &mem->swapout.meta_len);
    debug(20, 3) ("storeBuildSwapFileHeader: len=%d.\n", mem->swapout.meta_len);
    if (swap_buf_c)
	xmemcpy(swap_buf_c, mem->swapout.meta_buf, mem->swapout.meta_len);
    return mem->swapout.meta_len;
}

int
getSwapHdr(int *type, int *len, void *dst, char *write_buf, int hdr_len)
{
    static int cur = 0;
    static char *curptr;
    char *tmp_buf;
    if (cur == 0 || curptr != write_buf) {	/* first call or rewind ! */
	cur = STORE_META_TLD_START;
	curptr = write_buf;
    }
    if (cur + STORE_META_TLD_START > hdr_len) {
	debug(20, 3) ("getSwapHdr: overflow, %d %d.\n", cur, hdr_len);
	cur = 0;
	return -1;
    }
    tmp_buf = &write_buf[cur];	/* position ourselves */
    xmemcpy(len, SwapMetaSize(tmp_buf), sizeof(int));	/* length */
    *type = SwapMetaType(tmp_buf);	/* type */
    xmemcpy(dst, SwapMetaData(tmp_buf), *len);	/* data */
    cur += STORE_META_TLD_START + *len;	/* advance position */
    debug(20, 4) ("getSwapHdr: t=%d l=%d (cur=%d hdr_len=%d) (%p)\n",
	*type, *len, cur, hdr_len, dst);
    if (cur == hdr_len) {
	debug(20, 4) ("getSwapHdr: finished with this.\n");
	cur = 0;
	return 1;
    }
    return 1;			/* ok ! */
}

void
addSwapHdr(int type, int len, void *src, char *write_buf, int *write_len)
{
    int hdr_len = *write_len;
    char *base = &write_buf[hdr_len];
    debug(20, 3) ("addSwapHdr: at %d\n", hdr_len);
    base[0] = (char) type;
    xmemcpy(&base[1], &len, sizeof(int));
    xmemcpy(SwapMetaData(base), src, len);
    hdr_len += STORE_META_TLD_START + len;
    /* now we know length */
    debug(20, 3) ("addSwapHdr: added type=%d len=%d data=%p. hdr_len=%d\n",
	type, len, src, hdr_len);
    /* update header */
    xmemcpy(&write_buf[1], &hdr_len, sizeof(int));
    *write_len = hdr_len;
}

int
storeGetMetaBuf(const char *buf, MemObject * mem)
{
    int hdr_len;
    assert(mem != NULL);
    /* the key */
    if (SwapMetaType(buf) != META_OK) {
	debug(20, 1) ("storeGetMetaBuf:Found an old-style object, damn.\n");
	return -1;
    }
    xmemcpy(&hdr_len, SwapMetaSize(buf), sizeof(int));
    mem->swapout.meta_len = hdr_len;
    mem->swapout.meta_buf = xmalloc(hdr_len);
    xmemcpy(mem->swapout.meta_buf, buf, hdr_len);
    debug(20, 3) (" header size %d\n", hdr_len);
    return hdr_len;
}

#if OLD_CODE
static int
storeParseMetaBuf(StoreEntry * e)
{
    static char mbuf[1024];
    int myt, myl;
    MemObject *mem = e->mem_obj;
    assert(e && e->mem_obj && e->key);
    getSwapHdr(&myt, &myl, mbuf, mem->swapout.meta_buf, mem->swapout.meta_len);
    mbuf[myl] = 0;
    debug(20, 3) ("storeParseMetaBuf: key=%s\n", mbuf);
    e->key = xstrdup(storeKeyScan(mbuf));
    getSwapHdr(&myt, &myl, &e->timestamp, mem->swapout.meta_buf, mem->swapout.meta_len);
    return 1;
}
#endif
