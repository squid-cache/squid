
/*
 * $Id: store_dir.cc,v 1.56 1998/02/13 18:16:06 wessels Exp $
 *
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

#define SWAP_DIR_SHIFT 24
#define SWAP_FILE_MASK 0x00FFFFFF
#define DefaultLevelOneDirs     16
#define DefaultLevelTwoDirs     256

static char *storeSwapSubDir(int dirn, int subdirn);
static int storeMostFreeSwapDir(void);
static int storeVerifyDirectory(const char *path);
static void storeCreateDirectory(const char *path, int lvl);
static void storeCreateSwapSubDirs(int j);

/* return full name to swapfile */
char *
storeSwapFullPath(int fn, char *fullpath)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    int dirn = (fn >> SWAP_DIR_SHIFT) % Config.cacheSwap.n_configured;
    int filn = fn & SWAP_FILE_MASK;
    int L1 = Config.cacheSwap.swapDirs[dirn].l1;
    int L2 = Config.cacheSwap.swapDirs[dirn].l2;
    if (!fullpath)
	fullpath = fullfilename;
    fullpath[0] = '\0';
    snprintf(fullpath, SQUID_MAXPATHLEN, "%s/%02X/%02X/%08X",
	Config.cacheSwap.swapDirs[dirn].path,
	((filn / L2) / L2) % L1,
	(filn / L2) % L2,
	filn);
    return fullpath;
}

static char *
storeSwapSubDir(int dirn, int subdirn)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    SwapDir *SD;
    assert(0 <= dirn && dirn < Config.cacheSwap.n_configured);
    SD = &Config.cacheSwap.swapDirs[dirn];
    assert(0 <= subdirn && subdirn < SD->l1);
    snprintf(fullfilename, SQUID_MAXPATHLEN, "%s/%02X",
	Config.cacheSwap.swapDirs[dirn].path,
	subdirn);
    return fullfilename;
}

char *
storeSwapSubSubDir(int fn, char *fullpath)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    int dirn = (fn >> SWAP_DIR_SHIFT) % Config.cacheSwap.n_configured;
    int filn = fn & SWAP_FILE_MASK;
    int L1 = Config.cacheSwap.swapDirs[dirn].l1;
    int L2 = Config.cacheSwap.swapDirs[dirn].l2;
    if (!fullpath)
	fullpath = fullfilename;
    fullpath[0] = '\0';
    snprintf(fullpath, SQUID_MAXPATHLEN, "%s/%02X/%02X",
	Config.cacheSwap.swapDirs[dirn].path,
	((filn / L2) / L2) % L1,
	(filn / L2) % L2);
    return fullpath;
}

/*
 * Does swapfile number 'fn' belong in cachedir #F0,
 * level1 dir #F1, level2 dir #F2?
 *
 * This is called by storeDirClean(), but placed here because
 * the algorithm needs to match storeSwapSubSubDir().
 *
 * Don't check that (fn >> SWAP_DIR_SHIFT) == F0 because
 * 'fn' may not have the directory bits set.
 */
int
storeFilenoBelongsHere(int fn, int F0, int F1, int F2)
{
    int D1, D2;
    int L1, L2;
    int filn = fn & SWAP_FILE_MASK;
    assert(F0 < Config.cacheSwap.n_configured);
    L1 = Config.cacheSwap.swapDirs[F0].l1;
    L2 = Config.cacheSwap.swapDirs[F0].l2;
    D1 = ((filn / L2) / L2) % L1;
    if (F1 != D1)
	return 0;
    D2 = (filn / L2) % L2;
    if (F2 != D2)
	return 0;
    return 1;
}

static void
storeCreateDirectory(const char *path, int lvl)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
	debug(20, lvl) ("%s exists\n", path);
    } else if (mkdir(path, 0755) == 0) {
	debug(20, lvl) ("%s created\n", path);
    } else if (errno == EEXIST) {
	debug(20, lvl) ("%s exists\n", path);
    } else {
	snprintf(tmp_error_buf, ERROR_BUF_SZ,
	    "Failed to make swap directory %s: %s",
	    path, xstrerror());
	fatal(tmp_error_buf);
    }
}

static int
storeVerifyDirectory(const char *path)
{
    struct stat sb;
    if (stat(path, &sb) < 0) {
	debug(20, 0) ("%s: %s\n", path, xstrerror());
	return -1;
    }
    if (S_ISDIR(sb.st_mode) == 0) {
	debug(20, 0) ("%s is not a directory\n", path);
	return -1;
    }
    return 0;
}

/*
 * This function is called by storeInit().  If this returns < 0,
 * then Squid exits, complains about swap directories not
 * existing, and instructs the admin to run 'squid -z'
 */
int
storeVerifyCacheDirs(void)
{
    int i;
    int j;
    const char *path;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	path = Config.cacheSwap.swapDirs[i].path;
	if (storeVerifyDirectory(path) < 0)
	    return -1;
	for (j = 0; j < Config.cacheSwap.swapDirs[i].l1; j++) {
	    path = storeSwapSubDir(i, j);
	    if (storeVerifyDirectory(path) < 0)
		return -1;
	}
    }
    return 0;
}

void
storeCreateSwapDirectories(void)
{
    int i;
    const char *path = NULL;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	path = Config.cacheSwap.swapDirs[i].path;
	debug(47, 3) ("Creating swap space in %s\n", path);
	storeCreateDirectory(path, 0);
	storeCreateSwapSubDirs(i);
    }
}

static void
storeCreateSwapSubDirs(int j)
{
    int i, k;
    SwapDir *SD = &Config.cacheSwap.swapDirs[j];
    LOCAL_ARRAY(char, name, MAXPATHLEN);
    for (i = 0; i < SD->l1; i++) {
	snprintf(name, MAXPATHLEN, "%s/%02X", SD->path, i);
	storeCreateDirectory(name, 0);
	debug(47, 1) ("Making directories in %s\n", name);
	for (k = 0; k < SD->l2; k++) {
	    snprintf(name, MAXPATHLEN, "%s/%02X/%02X", SD->path, i, k);
	    storeCreateDirectory(name, 2);
	}
    }
}

static int
storeMostFreeSwapDir(void)
{
    double least_used = 1.0;
    double this_used;
    int dirn = 0;
    int i;
    SwapDir *SD;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];
	this_used = (double) SD->cur_size / SD->max_size;
	if (this_used > least_used)
	    continue;
	if (SD->read_only)
	    continue;
	least_used = this_used;
	dirn = i;
    }
    return dirn;
}

int
storeDirValidFileno(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    if (dirn > Config.cacheSwap.n_configured)
	return 0;
    if (dirn < 0)
	return 0;
    if (filn < 0)
	return 0;
    if (filn > Config.cacheSwap.swapDirs[dirn].map->max_n_files)
	return 0;
    return 1;
}

int
storeDirMapBitTest(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    return file_map_bit_test(Config.cacheSwap.swapDirs[dirn].map, filn);
}

void
storeDirMapBitSet(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    file_map_bit_set(Config.cacheSwap.swapDirs[dirn].map, filn);
}

void
storeDirMapBitReset(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    file_map_bit_reset(Config.cacheSwap.swapDirs[dirn].map, filn);
}

int
storeDirMapAllocate(void)
{
    int dirn = storeMostFreeSwapDir();
    SwapDir *SD = &Config.cacheSwap.swapDirs[dirn];
    int filn = file_map_allocate(SD->map, SD->suggest);
    SD->suggest = filn + 1;
    return (dirn << SWAP_DIR_SHIFT) | (filn & SWAP_FILE_MASK);
}

char *
storeSwapDir(int dirn)
{
    assert(0 <= dirn && dirn < Config.cacheSwap.n_configured);
    return Config.cacheSwap.swapDirs[dirn].path;
}

int
storeDirNumber(int swap_file_number)
{
    return swap_file_number >> SWAP_DIR_SHIFT;
}

int
storeDirProperFileno(int dirn, int fn)
{
    return (dirn << SWAP_DIR_SHIFT) | (fn & SWAP_FILE_MASK);
}

/*
 * An entry written to the swap log MUST have the following
 * properties.
 *   1.  It MUST be a public key.  It does no good to log
 *       a public ADD, change the key, then log a private
 *       DEL.  So we need to log a DEL before we change a
 *       key from public to private.
 *   2.  It MUST have a valid (> -1) swap_file_number.
 */
void
storeDirSwapLog(const StoreEntry * e, int op)
{
    storeSwapLogData *s;
    int dirn;
    dirn = e->swap_file_number >> SWAP_DIR_SHIFT;
    assert(dirn < Config.cacheSwap.n_configured);
    assert(!EBIT_TEST(e->flag, KEY_PRIVATE));
    assert(e->swap_file_number >= 0);
    /*
     * icons and such; don't write them to the swap log
     */
    if (EBIT_TEST(e->flag, ENTRY_SPECIAL))
	return;
    assert(op > SWAP_LOG_NOP && op < SWAP_LOG_MAX);
    debug(20, 3) ("storeDirSwapLog: %s %s %08X\n",
	swap_log_op_str[op],
	storeKeyText(e->key),
	e->swap_file_number);
    s = xcalloc(1, sizeof(storeSwapLogData));
    s->op = (char) op;
    s->swap_file_number = e->swap_file_number;
    s->timestamp = e->timestamp;
    s->lastref = e->lastref;
    s->expires = e->expires;
    s->lastmod = e->lastmod;
    s->swap_file_sz = e->swap_file_sz;
    s->refcount = e->refcount;
    s->flags = e->flag;
    xmemcpy(s->key, e->key, MD5_DIGEST_CHARS);
    file_write(Config.cacheSwap.swapDirs[dirn].swaplog_fd,
	-1,
	s,
	sizeof(storeSwapLogData),
	NULL,
	NULL,
	xfree);
}

char *
storeDirSwapLogFile(int dirn, const char *ext)
{
    LOCAL_ARRAY(char, path, SQUID_MAXPATHLEN);
    LOCAL_ARRAY(char, digit, 32);
    if (Config.Log.swap) {
	xstrncpy(path, Config.Log.swap, SQUID_MAXPATHLEN - 64);
	strcat(path, ".");
	snprintf(digit, 32, "%02d", dirn);
	strncat(path, digit, 3);
    } else {
	xstrncpy(path, storeSwapDir(dirn), SQUID_MAXPATHLEN - 64);
	strcat(path, "/swap.state");
    }
    if (ext)
	strncat(path, ext, 16);
    return path;
}

void
storeDirOpenSwapLogs(void)
{
    int i;
    char *path;
    int fd;
    SwapDir *SD;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];
	path = storeDirSwapLogFile(i, NULL);
	fd = file_open(path, O_WRONLY | O_CREAT, NULL, NULL, NULL);
	if (fd < 0) {
	    debug(50, 1) ("%s: %s\n", path, xstrerror());
	    fatal("storeDirOpenSwapLogs: Failed to open swap log.");
	}
	debug(47, 3) ("Cache Dir #%d log opened on FD %d\n", i, fd);
	SD->swaplog_fd = fd;
    }
}

void
storeDirCloseSwapLogs(void)
{
    int i;
    SwapDir *SD;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];
	if (SD->swaplog_fd < 0)	/* not open */
	    continue;
	file_close(SD->swaplog_fd);
	debug(47, 3) ("Cache Dir #%d log closed on FD %d\n", i, SD->swaplog_fd);
	SD->swaplog_fd = -1;
    }
}

FILE *
storeDirOpenTmpSwapLog(int dirn, int *clean_flag, int *zero_flag)
{
    char *swaplog_path = xstrdup(storeDirSwapLogFile(dirn, NULL));
    char *clean_path = xstrdup(storeDirSwapLogFile(dirn, ".last-clean"));
    char *new_path = xstrdup(storeDirSwapLogFile(dirn, ".new"));
    struct stat log_sb;
    struct stat clean_sb;
    SwapDir *SD = &Config.cacheSwap.swapDirs[dirn];
    FILE *fp;
    int fd;
    if (stat(swaplog_path, &log_sb) < 0) {
	debug(47, 1) ("Cache Dir #%d: No log file\n", dirn);
	safe_free(swaplog_path);
	safe_free(clean_path);
	safe_free(new_path);
	return NULL;
    }
    *zero_flag = log_sb.st_size == 0 ? 1 : 0;
    /* close the existing write-only FD */
    if (SD->swaplog_fd >= 0)
	file_close(SD->swaplog_fd);
    /* open a write-only FD for the new log */
    fd = file_open(new_path, O_WRONLY | O_CREAT | O_TRUNC, NULL, NULL, NULL);
    if (fd < 0) {
	debug(50, 1) ("%s: %s\n", new_path, xstrerror());
	fatal("storeDirOpenTmpSwapLog: Failed to open swap log.");
    }
    SD->swaplog_fd = fd;
    /* open a read-only stream of the old log */
    fp = fopen(swaplog_path, "r");
    if (fp == NULL) {
	debug(50, 0) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("Failed to open swap log for reading");
    }
    memset(&clean_sb, '\0', sizeof(struct stat));
    if (stat(clean_path, &clean_sb) < 0)
	*clean_flag = 0;
    else if (clean_sb.st_mtime < log_sb.st_mtime)
	*clean_flag = 0;
    else
	*clean_flag = 1;
    safeunlink(clean_path, 1);
    safe_free(swaplog_path);
    safe_free(clean_path);
    safe_free(new_path);
    return fp;
}

void
storeDirCloseTmpSwapLog(int dirn)
{
    char *swaplog_path = xstrdup(storeDirSwapLogFile(dirn, NULL));
    char *new_path = xstrdup(storeDirSwapLogFile(dirn, ".new"));
    SwapDir *SD = &Config.cacheSwap.swapDirs[dirn];
    int fd;
    if (rename(new_path, swaplog_path) < 0) {
	debug(50, 0) ("%s,%s: %s\n", new_path, swaplog_path, xstrerror());
	fatal("storeDirCloseTmpSwapLog: rename failed");
    }
    file_close(SD->swaplog_fd);
    fd = file_open(swaplog_path, O_WRONLY | O_CREAT, NULL, NULL, NULL);
    if (fd < 0) {
	debug(50, 1) ("%s: %s\n", swaplog_path, xstrerror());
	fatal("storeDirCloseTmpSwapLog: Failed to open swap log.");
    }
    safe_free(swaplog_path);
    safe_free(new_path);
    SD->swaplog_fd = fd;
    debug(47, 3) ("Cache Dir #%d log opened on FD %d\n", dirn, fd);
}

void
storeDirUpdateSwapSize(int fn, size_t size, int sign)
{
    int dirn = (fn >> SWAP_DIR_SHIFT) % Config.cacheSwap.n_configured;
    int k = ((size + 1023) >> 10) * sign;
    Config.cacheSwap.swapDirs[dirn].cur_size += k;
    store_swap_size += k;
}

void
storeDirStats(StoreEntry * sentry)
{
    int i;
    SwapDir *SD;
    storeAppendPrintf(sentry, "Store Directory Statistics:\n");
    storeAppendPrintf(sentry, "Store Entries          : %d\n",
	memInUse(MEM_STOREENTRY));
    storeAppendPrintf(sentry, "Maximum Swap Size      : %8d KB\n",
	Config.Swap.maxSize);
    storeAppendPrintf(sentry, "Current Store Swap Size: %8d KB\n",
	store_swap_size);
    storeAppendPrintf(sentry, "Current Capacity       : %d%% used, %d%% free\n",
	percent((int) store_swap_size, (int) Config.Swap.maxSize),
	percent((int) (Config.Swap.maxSize - store_swap_size), (int) Config.Swap.maxSize));
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];
	storeAppendPrintf(sentry, "\n");
	storeAppendPrintf(sentry, "Store Directory #%d: %s\n", i, SD->path);
	storeAppendPrintf(sentry, "First level subdirectories: %d\n", SD->l1);
	storeAppendPrintf(sentry, "Second level subdirectories: %d\n", SD->l2);
	storeAppendPrintf(sentry, "Maximum Size: %d KB\n", SD->max_size);
	storeAppendPrintf(sentry, "Current Size: %d KB\n", SD->cur_size);
	storeAppendPrintf(sentry, "Percent Used: %0.2f%%\n",
	    100.0 * SD->cur_size / SD->max_size);
    }
}

/*
 *  storeDirWriteCleanLogs
 * 
 *  Writes a "clean" swap log file from in-memory metadata.
 */
#define CLEAN_BUF_SZ 16384
int
storeDirWriteCleanLogs(int reopen)
{
    StoreEntry *e = NULL;
    int *fd;
    int n = 0;
    time_t start, stop, r;
    struct stat sb;
    char **cur;
    char **new;
    char **cln;
    int dirn;
    dlink_node *m;
    char **outbuf;
    off_t *outbufoffset;
    storeSwapLogData *s;
    if (store_rebuilding) {
	debug(20, 1) ("Not currently OK to rewrite swap log.\n");
	debug(20, 1) ("storeDirWriteCleanLogs: Operation aborted.\n");
	storeDirCloseSwapLogs();
	return 0;
    }
    debug(20, 1) ("storeDirWriteCleanLogs: Starting...\n");
    start = squid_curtime;
    fd = xcalloc(Config.cacheSwap.n_configured, sizeof(int));
    cur = xcalloc(Config.cacheSwap.n_configured, sizeof(char *));
    new = xcalloc(Config.cacheSwap.n_configured, sizeof(char *));
    cln = xcalloc(Config.cacheSwap.n_configured, sizeof(char *));
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	fd[dirn] = -1;
	cur[dirn] = xstrdup(storeDirSwapLogFile(dirn, NULL));
	new[dirn] = xstrdup(storeDirSwapLogFile(dirn, ".clean"));
	cln[dirn] = xstrdup(storeDirSwapLogFile(dirn, ".last-clean"));
	unlink(new[dirn]);
	unlink(cln[dirn]);
	fd[dirn] = file_open(new[dirn],
	    O_WRONLY | O_CREAT | O_TRUNC,
	    NULL,
	    NULL,
	    NULL);
	if (fd[dirn] < 0) {
	    debug(50, 0) ("storeDirWriteCleanLogs: %s: %s\n", new[dirn], xstrerror());
	    continue;
	}
	debug(20, 3) ("storeDirWriteCleanLogs: opened %s, FD %d\n",
	    new[dirn], fd[dirn]);
#if HAVE_FCHMOD
	if (stat(cur[dirn], &sb) == 0)
	    fchmod(fd[dirn], sb.st_mode);
#endif
    }
    outbuf = xcalloc(Config.cacheSwap.n_configured, sizeof(char *));
    outbufoffset = xcalloc(Config.cacheSwap.n_configured, sizeof(int));
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	outbuf[dirn] = xcalloc(Config.cacheSwap.n_configured, CLEAN_BUF_SZ);
	outbufoffset[dirn] = 0;
    }
    for (m = store_list.tail; m; m = m->prev) {
	e = m->data;
	if (e->swap_file_number < 0)
	    continue;
	if (e->swap_status != SWAPOUT_DONE)
	    continue;
	if (e->swap_file_sz <= 0)
	    continue;
	if (EBIT_TEST(e->flag, RELEASE_REQUEST))
	    continue;
	if (EBIT_TEST(e->flag, KEY_PRIVATE))
	    continue;
	if (EBIT_TEST(e->flag, ENTRY_SPECIAL))
	    continue;
	dirn = storeDirNumber(e->swap_file_number);
	assert(dirn < Config.cacheSwap.n_configured);
	if (fd[dirn] < 0)
	    continue;
	s = (storeSwapLogData *) (outbuf[dirn] + outbufoffset[dirn]);
	outbufoffset[dirn] += sizeof(storeSwapLogData);
	memset(s, '\0', sizeof(storeSwapLogData));
	s->op = (char) SWAP_LOG_ADD;
	s->swap_file_number = e->swap_file_number;
	s->timestamp = e->timestamp;
	s->lastref = e->lastref;
	s->expires = e->expires;
	s->lastmod = e->lastmod;
	s->swap_file_sz = e->swap_file_sz;
	s->refcount = e->refcount;
	s->flags = e->flag;
	xmemcpy(s->key, e->key, MD5_DIGEST_CHARS);
	/* buffered write */
	if (outbufoffset[dirn] + sizeof(storeSwapLogData) > CLEAN_BUF_SZ) {
	    if (write(fd[dirn], outbuf[dirn], outbufoffset[dirn]) < 0) {
		debug(50, 0) ("storeDirWriteCleanLogs: %s: write: %s\n",
		    new[dirn], xstrerror());
		debug(20, 0) ("storeDirWriteCleanLogs: Current swap logfile not replaced.\n");
		file_close(fd[dirn]);
		fd[dirn] = -1;
		unlink(new[dirn]);
		continue;
	    }
	    outbufoffset[dirn] = 0;
	}
	if ((++n & 0x3FFF) == 0) {
	    getCurrentTime();
	    debug(20, 1) ("  %7d entries written so far.\n", n);
	}
    }
    /* flush */
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	if (outbufoffset[dirn] == 0)
	    continue;
	if (fd[dirn] < 0)
	    continue;
	if (write(fd[dirn], outbuf[dirn], outbufoffset[dirn]) < 0) {
	    debug(50, 0) ("storeDirWriteCleanLogs: %s: write: %s\n",
		new[dirn], xstrerror());
	    debug(20, 0) ("storeDirWriteCleanLogs: Current swap logfile not replaced.\n");
	    file_close(fd[dirn]);
	    fd[dirn] = -1;
	    unlink(new[dirn]);
	    continue;
	}
	safe_free(outbuf[dirn]);
    }
    safe_free(outbuf);
    safe_free(outbufoffset);
    /* rename */
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	if (fd[dirn] < 0)
	    continue;
	if (rename(new[dirn], cur[dirn]) < 0) {
	    debug(50, 0) ("storeDirWriteCleanLogs: rename failed: %s, %s -> %s\n",
		xstrerror(), new[dirn], cur[dirn]);
	}
    }
    storeDirCloseSwapLogs();
    if (reopen)
	storeDirOpenSwapLogs();
    stop = squid_curtime;
    r = stop - start;
    debug(20, 1) ("  Finished.  Wrote %d entries.\n", n);
    debug(20, 1) ("  Took %d seconds (%6.1lf entries/sec).\n",
	r > 0 ? r : 0, (double) n / (r > 0 ? r : 1));
    /* touch a timestamp file if we're not still validating */
    if (!store_rebuilding) {
	for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	    if (fd[dirn] < 0)
		continue;
	    file_close(file_open(cln[dirn],
		    O_WRONLY | O_CREAT | O_TRUNC, NULL, NULL, NULL));
	}
    }
    /* close */
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	safe_free(cur[dirn]);
	safe_free(new[dirn]);
	safe_free(cln[dirn]);
	if (fd[dirn] < 0)
	    continue;
	file_close(fd[dirn]);
	fd[dirn] = -1;
    }
    safe_free(cur);
    safe_free(new);
    safe_free(cln);
    safe_free(fd);
    return n;
}
#undef CLEAN_BUF_SZ
