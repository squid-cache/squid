#include "squid.h"

#define STORE_META_BUFSZ 4096

struct _rebuild_dir {
    int dirn;
    FILE *log;
    int speed;
    int clean;
    struct _rebuild_dir *next;
};

struct storeRebuildState {
    struct _rebuild_dir *rebuild_dir;
    int objcount;               /* # objects successfully reloaded */
    int expcount;               /* # objects expired */
    int linecount;              /* # lines parsed from cache logfile */
    int clashcount;             /* # swapfile clashes avoided */
    int cancelcount;            /* # objects cancelled */
    int dupcount;               /* # duplicates purged */
    int invalid;                /* # bad lines */
    int badflags;               /* # bad e->flags */
    int need_to_validate;
    time_t start;
    time_t stop;
    char *line_in;
    size_t line_in_sz;
};

typedef struct valid_ctrl_t {
    struct stat *sb;
    StoreEntry *e;
    STVLDCB *callback;
    void *callback_data;
} valid_ctrl_t;

static void storeRebuiltFromDisk(struct storeRebuildState *data);

void
storeDoRebuildFromSwapFiles(void *data)
{
    struct storeRebuildState *RB = data;
    LOCAL_ARRAY(char, hdr_buf, 2 * MAX_URL);
    LOCAL_ARRAY(cache_key, keybuf, MAX_URL);
    StoreEntry *e = NULL;
    StoreEntry tmpe;
    int sfileno = 0;
    int count;
    int size;
    int x;
    struct _rebuild_dir *d = RB->rebuild_dir;
    struct stat fst;
    static int filecount;
    int hdr_len = 0;
    int myt, myl;
    int fd = 0;
    debug(20, 3) (" Starting StoreRebuildFromSwapFiles at speed %d\n", d->speed);
    for (count = 0; count < d->speed; count++) {
	if (fd)
	    file_close(fd);
	fd = storeGetNextFile(&sfileno, &size);
	if (fd == -2) {
	    debug(20, 1) ("StoreRebuildFromSwapFiles: done!\n");
	    store_rebuilding = 0;
	    return;
	} else if (fd == 0) {
	    continue;
	}
	assert(fd > 0);
	/* lets get file stats here */
	x = fstat(fd, &fst);
	assert(x == 0);
	if ((++filecount & 0x3FFF) == 0)
	    debug(20, 1) ("  %7d objects read so far.\n", RB->linecount);
	debug(20, 9) ("file_in: fd=%d %08x\n", fd, sfileno);
	x = read(fd, hdr_buf, 4096);
	if (x < STORE_META_TLD_SIZE) {
	    debug(20, 1) (" Error reading header %s, small file, removing (read %d) %s\n",
		xstrerror(), x, hdr_buf);
	    safeunlink(storeSwapFullPath(sfileno, NULL), 1);
	    continue;
	}
	if (SwapMetaType(hdr_buf) != META_OK) {
	    debug(20, 1) ("  Found an old-style object or an invalid one\n");
	    safeunlink(storeSwapFullPath(sfileno, NULL), 1);
	    continue;
	}
	xmemcpy(&hdr_len, SwapMetaSize(hdr_buf), sizeof(int));
	if (x < hdr_len) {
	    debug(20, 1) ("  Error header size > x (%d)%d\n", hdr_len, x);
	    safeunlink(storeSwapFullPath(sfileno, NULL), 1);
	    continue;
	}
	debug(20, 3) (" header size %d\n", hdr_len);
	/* get key */
	if (0 == getSwapHdr(&myt, &myl, keybuf, hdr_buf, hdr_len)) {
	    debug(20, 1) ("Error getting STORE_META_KEY %d\n", x);
	    safeunlink(storeSwapFullPath(sfileno, NULL), 1);
	    continue;
	}
	keybuf[myl] = '\0';
	debug(20, 3) (" hm, we have %s, %d, %d\n", keybuf, myt, myl);
	if (keybuf[0] == '\0' || myt != STORE_META_KEY) {
	    debug(20, 1) ("storeDoRebuildFromSwapFiles: bad key\n");
	    safeunlink(storeSwapFullPath(sfileno, NULL), 1);
	    continue;
	}
	/* get the standard meta data for the StoreEntry */
	memset(&tmpe, '\0', sizeof(StoreEntry));
	if (0 == getSwapHdr(&myt, &myl, &tmpe.timestamp, hdr_buf, hdr_len)) {
	    debug(20, 1) ("storeDoRebuildFromSwapFiles:Error getting STORE_META_STD %d\n", myl);
	    safeunlink(storeSwapFullPath(sfileno, NULL), 1);
	    continue;
	}
	assert(myt == STORE_META_STD);
	assert(myl == STORE_HDR_METASIZE);
	/* check sizes */
	if (hdr_len + tmpe.object_len != fst.st_size) {
	    debug(20, 1) ("storeDoRebuildFromSwapFiles:INVALID swapfile, sizes dont match %d+%d!=%d\n",
		hdr_len, tmpe.object_len, fst.st_size);
	    safeunlink(storeSwapFullPath(sfileno, NULL), 1);
	    continue;
	}
	if (EBIT_TEST(tmpe.flag, KEY_PRIVATE)) {
	    safeunlink(storeSwapFullPath(sfileno, NULL), 1);
	    RB->badflags++;
	    continue;
	}
	if ((e = storeGet(keybuf)) != NULL) {
	    /* URL already exists, this swapfile not being used */
	    /* junk old, load new */
	    storeRelease(e);	/* release old entry */
	    RB->dupcount++;
	}
	/* update store_swap_size */
	RB->objcount++;
	debug(20, 4) ("storeDoRebuildFromSwapFiles: KEY=%20s , sfileno=%08X exp=%08X timest=%08X\n",
	    keybuf, sfileno, tmpe.expires, tmpe.timestamp);
	debug(20, 4) ("     			lastref=%08X lastmod=%08X refcount=%08X flag=%08X\n",
	    tmpe.lastref, tmpe.lastmod, tmpe.refcount, tmpe.flag);
	debug(20, 4) ("				len=%d hdr_len=%d file_len=%d\n", tmpe.object_len,
	    hdr_len, fst.st_size);
	e = storeAddDiskRestore(keybuf,
	    sfileno,
	    (int) tmpe.object_len,
	    tmpe.expires,
	    tmpe.timestamp,
	    tmpe.lastref,
	    tmpe.lastmod,
	    (u_num32) tmpe.refcount,	/* refcount */
	    (u_num32) tmpe.flag,	/* flags */
	    d->clean);
    }
    eventAdd("storeRebuild", storeDoRebuildFromSwapFiles, RB, 0);
}


void
storeConvert(void)
{
    int i;
    struct storeRebuildState *RB;
    struct _rebuild_dir *d;
    FILE *fp;
    int clean;
    RB = xcalloc(1, sizeof(struct storeRebuildState));
    RB->start = squid_curtime;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	fp = storeDirOpenTmpSwapLog(i, &clean);
	if (fp == NULL)
	    continue;
	d = xcalloc(1, sizeof(struct _rebuild_dir));
	d->dirn = i;
	d->log = fp;
	d->clean = clean;
	d->speed = 1 << 30;
	d->next = RB->rebuild_dir;
	RB->rebuild_dir = d;
	if (!clean)
	    RB->need_to_validate = 1;
	debug(20, 1) ("Converting storage in Cache Dir #%d (%s)\n",
	    i, clean ? "CLEAN" : "DIRTY");
    }
    RB->line_in_sz = 4096;
    RB->line_in = xcalloc(1, RB->line_in_sz);
    storeDoConvertFromLog(RB);
}

void
storeConvertFile(const cache_key * key,
    int file_number,
    int size,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_short refcount,
    u_short flags,
    int clean)
{
    int fd_r, fd_w;
    int hdr_len, x, y;
    LOCAL_ARRAY(char, swapfilename, SQUID_MAXPATHLEN);
    LOCAL_ARRAY(char, copybuf, STORE_META_BUFSZ);
    StoreEntry e;
    e.key = key;
    e.object_len = size;
    e.expires = expires;
    e.lastref = lastref;
    e.refcount = refcount;
    e.flag = flags;
    storeSwapFullPath(file_number, swapfilename);
    fd_r = open(swapfilename, O_RDONLY);
    if (fd_r < 0) {		/* ERROR */
	return;
    }
    safeunlink(swapfilename, 1);
    fd_w = open(swapfilename, O_CREAT | O_WRONLY | O_TRUNC);
    hdr_len = storeBuildMetaData(&e, copybuf);
    assert(hdr_len < STORE_META_BUFSZ);
    x = write(fd_w, copybuf, hdr_len);
    while (x > 0) {
	y = read(fd_r, copybuf, STORE_META_BUFSZ);
	x = write(fd_w, copybuf, y);
    }
    close(fd_r);
    close(fd_w);
}

int
storeGetNextFile(int *sfileno, int *size)
{
    static int dirn, curlvl1, curlvl2, flag, done, in_dir, fn;
    static struct dirent *entry;
    static DIR *td;
    int fd = 0, used = 0;
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    LOCAL_ARRAY(char, fullpath, SQUID_MAXPATHLEN);
    debug(20, 3) ("storeGetNextFile: flag=%d, %d: /%02X/%02X\n", flag,
	dirn, curlvl1, curlvl2);
    if (done)
	return -2;
    while (!fd && !done) {
	fd = 0;
	if (!flag) {		/* initialize, open first file */
	    done = dirn = curlvl1 = curlvl2 = in_dir = 0;
	    flag = 1;
	    assert(Config.cacheSwap.n_configured > 0);
	}
	if (!in_dir) {		/* we need to read in a new directory */
	    snprintf(fullpath, SQUID_MAXPATHLEN, "%s/%02X/%02X",
		Config.cacheSwap.swapDirs[dirn].path,
		curlvl1, curlvl2);
	    if (flag && td)
		closedir(td);
	    td = opendir(fullpath);
	    entry = readdir(td);	/* skip . and .. */
	    entry = readdir(td);
	    if (errno == ENOENT) {
		debug(20, 3) ("storeGetNextFile: directory does not exist!.\n");
	    }
	    debug(20, 3) ("storeGetNextFile: Directory %s/%02X/%02X\n",
		Config.cacheSwap.swapDirs[dirn].path,
		curlvl1, curlvl2);
	}
	if ((entry = readdir(td))) {
	    in_dir++;
	    if (sscanf(entry->d_name, "%x", sfileno) != 1) {
		debug(20, 3) ("storeGetNextFile: invalid %s\n",
		    entry->d_name);
		continue;
	    }
	    fn = *sfileno;
	    fn = storeDirProperFileno(dirn, fn);
	    *sfileno = fn;
	    used = storeDirMapBitTest(fn);
	    if (used) {
		debug(20, 3) ("storeGetNextFile: Locked, continuing with next.\n");
		continue;
	    }
	    snprintf(fullfilename, SQUID_MAXPATHLEN, "%s/%s",
		fullpath, entry->d_name);
	    debug(20, 3) ("storeGetNextFile: Opening %s\n", fullfilename);
	    fd = file_open(fullfilename, O_RDONLY, NULL, NULL, NULL);
	    continue;
	}
#if 0
	else if (!in_dir)
	    debug(20, 3) ("storeGetNextFile: empty dir.\n");
#endif
	in_dir = 0;
	if ((curlvl2 = (curlvl2 + 1) % Config.cacheSwap.swapDirs[dirn].l2) != 0)
	    continue;
	if ((curlvl1 = (curlvl1 + 1) % Config.cacheSwap.swapDirs[dirn].l1) != 0)
	    continue;
	if ((dirn = (dirn + 1) % Config.cacheSwap.n_configured) != 0)
	    continue;
	else
	    done = 1;
    }
    return fd;
}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. */
StoreEntry *
storeAddDiskRestore(const cache_key * key,
    int file_number,
    int size,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_num32 refcount,
    u_num32 flags,
    int clean)
{
    StoreEntry *e = NULL;
    debug(20, 5) ("StoreAddDiskRestore: %s, fileno=%08X\n", storeKeyText(key), file_number);
    /* if you call this you'd better be sure file_number is not 
     * already in use! */
    e = new_StoreEntry(STORE_ENTRY_WITHOUT_MEMOBJ, NULL, NULL);
    storeHashInsert(e, key);
    e->store_status = STORE_OK;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_DONE;
    e->swap_file_number = file_number;
    e->object_len = size;
    e->lock_count = 0;
    e->refcount = 0;
    e->lastref = lastref;
    e->timestamp = timestamp;
    e->expires = expires;
    e->lastmod = lastmod;
    e->refcount = refcount;
    e->flag = flags;
    EBIT_SET(e->flag, ENTRY_CACHABLE);
    EBIT_CLR(e->flag, RELEASE_REQUEST);
    EBIT_CLR(e->flag, KEY_PRIVATE);
    e->ping_status = PING_NONE;
    EBIT_CLR(e->flag, ENTRY_VALIDATED);
    storeDirMapBitSet(e->swap_file_number);
    return e;
}

/* convert storage .. this is the old storeDoRebuildFromDisk() */

void
storeDoConvertFromLog(void *data)
{
    struct storeRebuildState *RB = data;
    LOCAL_ARRAY(char, swapfile, MAXPATHLEN);
    LOCAL_ARRAY(char, keytext, MAX_URL);
    StoreEntry *e = NULL;
    time_t expires;
    time_t timestamp;
    time_t lastref;
    time_t lastmod;
    int scan1;
    int scan2;
    int scan3;
    int scan4;
    int scan5;
    int scan6;
    int scan7;
    off_t size;
    int sfileno = 0;
    int count;
    int x;
    struct _rebuild_dir *d;
    struct _rebuild_dir **D;
    int used;			/* is swapfile already in use? */
    int newer;			/* is the log entry newer than current entry? */
    const cache_key *key;
    /* load a number of objects per invocation */
    if ((d = RB->rebuild_dir) == NULL) {
	debug(20, 3) ("Done Converting, here are the stats.\n");
	storeRebuiltFromDisk(RB);
	return;
    }
    for (count = 0; count < d->speed; count++) {
	if (fgets(RB->line_in, RB->line_in_sz, d->log) == NULL) {
	    debug(20, 1) ("Done reading Cache Dir #%d swap log\n", d->dirn);
	    fclose(d->log);
	    d->log = NULL;
	    storeDirCloseTmpSwapLog(d->dirn);
	    RB->rebuild_dir = d->next;
	    safe_free(d);
	    eventAdd("storeRebuild", storeDoConvertFromLog, RB, 0);
	    return;
	}
	if ((++RB->linecount & 0x3FFF) == 0)
	    debug(20, 1) ("  %7d Lines read so far.\n", RB->linecount);
	debug(20, 9) ("line_in: %s", RB->line_in);
	if (RB->line_in[0] == '\0')
	    continue;
	if (RB->line_in[0] == '\n')
	    continue;
	if (RB->line_in[0] == '#')
	    continue;
	keytext[0] = '\0';
	sfileno = 0;
	scan1 = 0;
	scan2 = 0;
	scan3 = 0;
	scan4 = 0;
	scan5 = 0;
	scan6 = 0;
	scan7 = 0;
	x = sscanf(RB->line_in, "%x %x %x %x %x %d %d %x %s",
	    &sfileno,		/* swap_file_number */
	    &scan1,		/* timestamp */
	    &scan2,		/* lastref */
	    &scan3,		/* expires */
	    &scan4,		/* last modified */
	    &scan5,		/* size */
	    &scan6,		/* refcount */
	    &scan7,		/* flags */
	    keytext);		/* key */
	if (x < 1) {
	    RB->invalid++;
	    continue;
	}
	if (x != 9) {
	    RB->invalid++;
	    continue;
	}
	timestamp = (time_t) scan1;
	lastref = (time_t) scan2;
	expires = (time_t) scan3;
	lastmod = (time_t) scan4;
	size = (off_t) scan5;
	if (size < 0) {
	    if ((key = storeKeyScan(keytext)) == NULL)
		continue;
	    if ((e = storeGet(key)) == NULL)
		continue;
	    if (e->lastref > lastref)
		continue;
	    debug(20, 3) ("storeRebuildFromDisk: Cancelling: '%s'\n", keytext);
	    storeRelease(e);
	    RB->objcount--;
	    RB->cancelcount++;
	    continue;
	}
	storeSwapFullPath(sfileno, swapfile);
	if (EBIT_TEST(scan7, KEY_PRIVATE)) {
	    RB->badflags++;
	    continue;
	}
	sfileno = storeDirProperFileno(d->dirn, sfileno);
	key = storeKeyScan(keytext);
	if (key == NULL) {
	    debug(20, 1) ("storeDoConvertFromLog: bad key: '%s'\n", keytext);
	    continue;
	}
	e = storeGet(key);
	used = storeDirMapBitTest(sfileno);
	/* If this URL already exists in the cache, does the swap log
	 * appear to have a newer entry?  Compare 'lastref' from the
	 * swap log to e->lastref. */
	newer = e ? (lastref > e->lastref ? 1 : 0) : 0;
	if (used && !newer) {
	    /* log entry is old, ignore it */
	    RB->clashcount++;
	    continue;
	} else if (used && e && e->swap_file_number == sfileno) {
	    /* swapfile taken, same URL, newer, update meta */
	    e->lastref = timestamp;
	    e->timestamp = timestamp;
	    e->expires = expires;
	    e->lastmod = lastmod;
	    e->flag |= (u_num32) scan6;
	    e->refcount += (u_num32) scan7;
	    continue;
	} else if (used) {
	    /* swapfile in use, not by this URL, log entry is newer */
	    /* This is sorta bad: the log entry should NOT be newer at this
	     * point.  If the log is dirty, the filesize check should have
	     * caught this.  If the log is clean, there should never be a
	     * newer entry. */
	    debug(20, 1) ("WARNING: newer swaplog entry for fileno %08X\n",
		sfileno);
	    /* I'm tempted to remove the swapfile here just to be safe,
	     * but there is a bad race condition in the NOVM version if
	     * the swapfile has recently been opened for writing, but
	     * not yet opened for reading.  Because we can't map
	     * swapfiles back to StoreEntrys, we don't know the state
	     * of the entry using that file.  */
	    /* We'll assume the existing entry is valid, probably because
	     * were in a slow rebuild and the the swap file number got taken
	     * and the validation procedure hasn't run. */
	    /* assert(RB->need_to_validate); */
	    RB->clashcount++;
	    continue;
	} else if (e) {
	    /* URL already exists, this swapfile not being used */
	    /* junk old, load new */
	    storeRelease(e);	/* release old entry */
	    RB->dupcount++;
	} else {
	    /* URL doesnt exist, swapfile not in use */
	    /* load new */
	    (void) 0;
	}
	/* update store_swap_size */
	RB->objcount++;
	storeConvertFile(key,
	    sfileno,
	    (int) size,
	    expires,
	    timestamp,
	    lastref,
	    lastmod,
	    (u_short) scan6,	/* refcount */
	    (u_short) scan7,	/* flags */
	    d->clean);
#if 0
	storeDirSwapLog(e);
#endif
    }
    RB->rebuild_dir = d->next;
    for (D = &RB->rebuild_dir; *D; D = &(*D)->next);
    *D = d;
    d->next = NULL;
    eventAdd("storeRebuild", storeDoConvertFromLog, RB, 0);
}

void
storeCleanup(void *datanotused)
{
    static int bucketnum = -1;
    static int validnum = 0;
    StoreEntry *e;
    hash_link *link_ptr = NULL;
    if (++bucketnum >= store_hash_buckets) {
	debug(20, 1) ("  Completed Validation Procedure\n");
	debug(20, 1) ("  Validated %d Entries\n", validnum);
	debug(20, 1) ("  store_swap_size = %dk\n", store_swap_size);
	store_rebuilding = 0;
	return;
    }
    link_ptr = hash_get_bucket(store_table, bucketnum);
    for (; link_ptr; link_ptr = link_ptr->next) {
	e = (StoreEntry *) link_ptr;
	if (EBIT_TEST(e->flag, ENTRY_VALIDATED))
	    continue;
	if (EBIT_TEST(e->flag, RELEASE_REQUEST))
	    continue;
	EBIT_SET(e->flag, ENTRY_VALIDATED);
	/* Only set the file bit if we know its a valid entry */
	/* otherwise, set it in the validation procedure */
	storeDirUpdateSwapSize(e->swap_file_number, e->object_len, 1);
	if ((++validnum & 0xFFFF) == 0)
	    debug(20, 1) ("  %7d Entries Validated so far.\n", validnum);
	assert(validnum <= memInUse(MEM_STOREENTRY));
    }
    eventAdd("storeCleanup", storeCleanup, NULL, 0);
}

#if OLD_CODE
void
storeCleanupComplete(void *data, int retcode, int errcode)
{
    StoreEntry *e = data;
    storeUnlockObject(e);
    outvalid--;
    if (retcode == -2 && errcode == -2)
	return;
    if (!EBIT_TEST(e->flag, ENTRY_VALIDATED))
	storeRelease(e);
}
#endif

void
storeValidate(StoreEntry * e, STVLDCB callback, void *callback_data, void *tag)
{
    valid_ctrl_t *ctrlp;
    char *path;
    struct stat *sb;
#if !USE_ASYNC_IO
    int x;
#endif
    assert(!EBIT_TEST(e->flag, ENTRY_VALIDATED));
    if (e->swap_file_number < 0) {
	EBIT_CLR(e->flag, ENTRY_VALIDATED);
	callback(callback_data, 0, 0);
	return;
    }
    path = storeSwapFullPath(e->swap_file_number, NULL);
    sb = xmalloc(sizeof(struct stat));
    ctrlp = xmalloc(sizeof(valid_ctrl_t));
    ctrlp->sb = sb;
    ctrlp->e = e;
    ctrlp->callback = callback;
    ctrlp->callback_data = callback_data;
#if USE_ASYNC_IO
    aioStat(path, sb, storeValidateComplete, ctrlp, tag);
#else
    /* When evaluating the actual arguments in a function call, the order
     * in which the arguments and the function expression are evaluated is
     * not specified; */
    x = stat(path, sb);
    storeValidateComplete(ctrlp, x, errno);
#endif
    return;
}

void
storeValidateComplete(void *data, int retcode, int errcode)
{
    valid_ctrl_t *ctrlp = data;
    struct stat *sb = ctrlp->sb;
    StoreEntry *e = ctrlp->e;
    char *path;

    if (retcode == -2 && errcode == -2) {
	xfree(sb);
	xfree(ctrlp);
	ctrlp->callback(ctrlp->callback_data, retcode, errcode);
	return;
    }
    if (retcode < 0 && errcode == EWOULDBLOCK) {
	path = storeSwapFullPath(e->swap_file_number, NULL);
	retcode = stat(path, sb);
    }
    if (retcode < 0 || sb->st_size == 0 || sb->st_size != e->object_len) {
	EBIT_CLR(e->flag, ENTRY_VALIDATED);
    } else {
	EBIT_SET(e->flag, ENTRY_VALIDATED);
	storeDirUpdateSwapSize(e->swap_file_number, e->object_len, 1);
    }
    errno = errcode;
    ctrlp->callback(ctrlp->callback_data, retcode, errcode);
    xfree(sb);
    xfree(ctrlp);
}

/* meta data recreated from disk image in swap directory */
static void
storeRebuiltFromDisk(struct storeRebuildState *data)
{
    time_t r;
    time_t stop;
    stop = squid_curtime;
    r = stop - data->start;
    debug(20, 1) ("Finished rebuilding storage from disk image.\n");
    debug(20, 1) ("  %7d Lines read from previous logfile.\n", data->linecount);
    debug(20, 1) ("  %7d Invalid lines.\n", data->invalid);
    debug(20, 1) ("  %7d With invalid flags.\n", data->badflags);
    debug(20, 1) ("  %7d Objects loaded.\n", data->objcount);
    debug(20, 1) ("  %7d Objects expired.\n", data->expcount);
    debug(20, 1) ("  %7d Objects cancelled.\n", data->cancelcount);
    debug(20, 1) ("  %7d Duplicate URLs purged.\n", data->dupcount);
    debug(20, 1) ("  %7d Swapfile clashes avoided.\n", data->clashcount);
    debug(20, 1) ("  Took %d seconds (%6.1lf objects/sec).\n",
	r > 0 ? r : 0, (double) data->objcount / (r > 0 ? r : 1));
    debug(20, 1) ("Beginning Validation Procedure\n");
    eventAdd("storeCleanup", storeCleanup, NULL, 0);
    memFree(MEM_4K_BUF, data->line_in);
    safe_free(data);
}

void
storeStartRebuildFromDisk(void)
{
    struct storeRebuildState *RB;
    struct _rebuild_dir *d;
    int clean = 1;
    RB = xcalloc(1, sizeof(struct storeRebuildState));
    RB->start = squid_curtime;
    d = xcalloc(1, sizeof(struct _rebuild_dir));
    d->clean = clean;
    d->speed = opt_foreground_rebuild ? 1 << 30 : 50;
    RB->rebuild_dir = d;
    if (!clean)
	RB->need_to_validate = 1;
    debug(20, 1) ("Rebuilding storage (%s)\n",
	clean ? "CLEAN" : "DIRTY");
    if (opt_foreground_rebuild) {
	storeDoRebuildFromSwapFiles(RB);
    } else {
	eventAdd("storeRebuild", storeDoRebuildFromSwapFiles, RB, 0);
    }
}
