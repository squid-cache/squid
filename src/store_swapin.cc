#include "squid.h"

typedef struct swapin_ctrl_t {
    StoreEntry *e;
    char *path;
    SIH *callback;
    void *callback_data;
    store_client *sc;
} swapin_ctrl_t;

/* start swapping in */
/* callback_data will become the tag on which the stat/open can be aborted */
void
storeSwapInStart(StoreEntry * e, SIH * callback, void *callback_data)
{
    swapin_ctrl_t *ctrlp;
    assert(e->mem_status == NOT_IN_MEMORY);
#if OLD_CODE
    if (!EBIT_TEST(e->flag, ENTRY_VALIDATED)) {
	if (storeDirMapBitTest(e->swap_file_number)) {
	    /* someone took our file while we weren't looking */
	    callback(-1, callback_data);
	    return;
	}
    }
#endif
    debug(20, 3) ("storeSwapInStart: called for %08X %s \n",
	e->swap_file_number, storeKeyText(e->key));
    assert(e->swap_status == SWAPOUT_WRITING || e->swap_status == SWAPOUT_DONE);
    assert(e->swap_file_number >= 0);
    assert(e->mem_obj != NULL);
    ctrlp = xmalloc(sizeof(swapin_ctrl_t));
    ctrlp->e = e;
    ctrlp->callback = callback;
    ctrlp->callback_data = callback_data;
    if (EBIT_TEST(e->flag, ENTRY_VALIDATED))
	storeSwapInValidateComplete(ctrlp, 0, 0);
    else
	storeValidate(e, storeSwapInValidateComplete, ctrlp, callback_data);
}

void
storeSwapInValidateComplete(void *data, int retcode, int errcode)
{
    swapin_ctrl_t *ctrlp = (swapin_ctrl_t *) data;
    StoreEntry *e;
    if (retcode == -2 && errcode == -2) {
	xfree(ctrlp);
	return;
    }
    e = ctrlp->e;
    assert(e->mem_status == NOT_IN_MEMORY);
    if (!EBIT_TEST(e->flag, ENTRY_VALIDATED)) {
	/* Invoke a store abort that should free the memory object */
	(ctrlp->callback) (-1, ctrlp->callback_data);
	xfree(ctrlp);
	return;
    }
    ctrlp->path = xstrdup(storeSwapFullPath(e->swap_file_number, NULL));
    debug(20, 3) ("storeSwapInValidateComplete: Opening %s\n", ctrlp->path);
    file_open(ctrlp->path,
	O_RDONLY,
	storeSwapInFileOpened,
	ctrlp,
	ctrlp->callback_data);
}

void
storeSwapInFileOpened(void *data, int fd, int errcode)
{
    swapin_ctrl_t *ctrlp = (swapin_ctrl_t *) data;
    StoreEntry *e = ctrlp->e;
    MemObject *mem = e->mem_obj;
    if (fd == -2 && errcode == -2) {
	xfree(ctrlp->path);
	xfree(ctrlp);
	return;
    }
    assert(mem != NULL);
    assert(e->mem_status == NOT_IN_MEMORY);
    assert(e->swap_status == SWAPOUT_WRITING || e->swap_status == SWAPOUT_DONE);
    if (fd < 0) {
	debug(20, 0) ("storeSwapInFileOpened: Failed '%s' for '%s'\n",
	    ctrlp->path, storeUrl(e));
	/* Invoke a store abort that should free the memory object */
	(ctrlp->callback) (-1, ctrlp->callback_data);
	xfree(ctrlp->path);
	xfree(ctrlp);
	return;
    }
    /*
     * We can't use fstat() to check file size here because of the
     * metadata header.  We have to parse the header first and find
     * the header size.
     */
#if OLD_CODE
    if (e->swap_status == SWAPOUT_DONE && fstat(fd, &sb) == 0) {
	if (sb.st_size == 0 || sb.st_size != e->object_len) {
	    debug(20, 0) ("storeSwapInFileOpened: %s: Size mismatch: %d(fstat) != %d(object)\n", ctrlp->path, sb.st_size, e->object_len);
	    file_close(fd);
	    fd = -1;
	}
    }
#endif
    debug(20, 5) ("storeSwapInFileOpened: initialized '%s' for '%s'\n",
	ctrlp->path, storeUrl(e));
    (ctrlp->callback) (fd, ctrlp->callback_data);
    xfree(ctrlp->path);
    xfree(ctrlp);
}

