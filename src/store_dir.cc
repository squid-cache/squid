
/*
 * $Id: store_dir.cc,v 1.27 1997/07/16 22:58:26 wessels Exp $
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

/* return full name to swapfile */
char *
storeSwapFullPath(int fn, char *fullpath)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    int dirn = (fn >> SWAP_DIR_SHIFT) % Config.cacheSwap.n_configured;
    int filn = fn & SWAP_FILE_MASK;
    if (!fullpath)
	fullpath = fullfilename;
    fullpath[0] = '\0';
    sprintf(fullpath, "%s/%02X/%02X/%08X",
	Config.cacheSwap.swapDirs[dirn].path,
	filn % Config.cacheSwap.swapDirs[dirn].l1,
	filn / Config.cacheSwap.swapDirs[dirn].l1 % Config.cacheSwap.swapDirs[dirn].l2,
	filn);
    return fullpath;
}

/* return full name to swapfile */
char *
storeSwapSubSubDir(int fn, char *fullpath)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    int dirn = (fn >> SWAP_DIR_SHIFT) % Config.cacheSwap.n_configured;
    int filn = fn & SWAP_FILE_MASK;
    if (!fullpath)
	fullpath = fullfilename;
    fullpath[0] = '\0';
    sprintf(fullpath, "%s/%02X/%02X",
	Config.cacheSwap.swapDirs[dirn].path,
	filn % Config.cacheSwap.swapDirs[dirn].l1,
	filn / Config.cacheSwap.swapDirs[dirn].l1 % Config.cacheSwap.swapDirs[dirn].l2);
    return fullpath;
}

static int
storeVerifyOrCreateDir(const char *path)
{
    struct stat sb;
    if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
	debug(47, 3) ("%s exists\n", path);
	return 0;
    }
    safeunlink(path, 1);
    if (mkdir(path, 0777) < 0) {
	if (errno != EEXIST) {
	    sprintf(tmp_error_buf, "Failed to create swap directory %s: %s",
		path,
		xstrerror());
	    fatal(tmp_error_buf);
	}
    }
    debug(47, 1) ("Created directory %s\n", path);
    if (stat(path, &sb) < 0 || !S_ISDIR(sb.st_mode)) {
	sprintf(tmp_error_buf,
	    "Failed to create directory %s: %s", path, xstrerror());
	fatal(tmp_error_buf);
    }
    return 1;
}

int
storeVerifySwapDirs(void)
{
    int i;
    const char *path = NULL;
    int directory_created = 0;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	path = Config.cacheSwap.swapDirs[i].path;
	debug(47, 3) ("storeVerifySwapDirs: Creating swap space in %s\n", path);
	storeVerifyOrCreateDir(path);
	storeCreateSwapSubDirs(i);
    }
    return directory_created;
}

void
storeCreateSwapSubDirs(int j)
{
    int i, k;
    SwapDir *SD = &Config.cacheSwap.swapDirs[j];
    LOCAL_ARRAY(char, name, MAXPATHLEN);
    for (i = 0; i < SD->l1; i++) {
	sprintf(name, "%s/%02X", SD->path, i);
	if (storeVerifyOrCreateDir(name) == 0)
	    continue;
	debug(47, 1) ("Making directories in %s\n", name);
	for (k = 0; k < SD->l2; k++) {
	    sprintf(name, "%s/%02X/%02X", SD->path, i, k);
	    storeVerifyOrCreateDir(name);
	}
    }
}

int
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
    Config.cacheSwap.swapDirs[dirn].suggest++;
}

void
storeDirMapBitReset(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    file_map_bit_reset(Config.cacheSwap.swapDirs[dirn].map, filn);
    if (fn < Config.cacheSwap.swapDirs[dirn].suggest)
	Config.cacheSwap.swapDirs[dirn].suggest = fn;
}

int
storeDirMapAllocate(void)
{
    int dirn = storeMostFreeSwapDir();
    SwapDir *SD = &Config.cacheSwap.swapDirs[dirn];
    int filn = file_map_allocate(SD->map, SD->suggest);
    return (dirn << SWAP_DIR_SHIFT) | (filn & SWAP_FILE_MASK);
}

char *
storeSwapDir(int dirn)
{
    if (dirn < 0 || dirn >= Config.cacheSwap.n_configured)
	fatal_dump("storeSwapDir: bad index");
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

void
storeDirSwapLog(const StoreEntry * e)
{
    LOCAL_ARRAY(char, logmsg, MAX_URL << 1);
    int dirn;
    if (e->swap_file_number < 0)
	fatal_dump("storeDirSwapLog: swap_file_number < 0");
    dirn = e->swap_file_number >> SWAP_DIR_SHIFT;
    assert(dirn < Config.cacheSwap.n_configured);
    if (BIT_TEST(e->flag, KEY_PRIVATE))
	debug(0, 0) ("storeDirSwapLog: PRIVATE: %s\n", e->url);
    /* Note this printf format appears in storeWriteCleanLog() too */
    sprintf(logmsg, "%08x %08x %08x %08x %08x %9d %6d %08x %s\n",
	(int) e->swap_file_number,
	(int) e->timestamp,
	(int) e->lastref,
	(int) e->expires,
	(int) e->lastmod,
	e->object_len,
	e->refcount,
	e->flag,
	e->url);
    file_write(Config.cacheSwap.swapDirs[dirn].swaplog_fd,
	xstrdup(logmsg),
	strlen(logmsg),
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
	sprintf(digit, "%02d", dirn);
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
	fd = file_open(path, O_WRONLY | O_CREAT, NULL, NULL);
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
	file_close(SD->swaplog_fd);
	debug(47, 3) ("Cache Dir #%d log closed on FD %d\n", i, SD->swaplog_fd);
	SD->swaplog_fd = -1;
    }
}

FILE *
storeDirOpenTmpSwapLog(int dirn, int *clean_flag)
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
    /* close the existing write-only FD */
    if (SD->swaplog_fd >= 0)
	file_close(SD->swaplog_fd);
    /* open a write-only FD for the new log */
    fd = file_open(new_path, O_WRONLY | O_CREAT | O_TRUNC, NULL, NULL);
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
    fd = file_open(swaplog_path, O_WRONLY | O_CREAT, NULL, NULL);
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
    storeAppendPrintf(sentry, "Store Entries: %d\n", meta_data.store_entries);
    storeAppendPrintf(sentry, "Store Swap Size: %d KB\n", store_swap_size);
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
