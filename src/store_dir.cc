#include "squid.h"
#include "filemap.h"
#include "store_dir.h"

#define SWAP_DIR_SHIFT 24
#define SWAP_FILE_MASK 0x00FFFFFF
#define DefaultLevelOneDirs     16
#define DefaultLevelTwoDirs     256

/* GLOBALS */
int ncache_dirs = 0;

/* LOCALS */
static int SwapDirsAllocated = 0;

/* return full name to swapfile */
char *
storeSwapFullPath(int fn, char *fullpath)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    int dirn = (fn >> SWAP_DIR_SHIFT) % ncache_dirs;
    int filn = fn & SWAP_FILE_MASK;
    if (!fullpath)
	fullpath = fullfilename;
    fullpath[0] = '\0';
    sprintf(fullpath, "%s/%02X/%02X/%08X",
	SwapDirs[dirn].path,
	filn % SwapDirs[dirn].l1,
	filn / SwapDirs[dirn].l1 % SwapDirs[dirn].l2,
	filn);
    return fullpath;
}

/* return full name to swapfile */
char *
storeSwapSubSubDir(int fn, char *fullpath)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN);
    int dirn = (fn >> SWAP_DIR_SHIFT) % ncache_dirs;
    int filn = fn & SWAP_FILE_MASK;
    if (!fullpath)
	fullpath = fullfilename;
    fullpath[0] = '\0';
    sprintf(fullpath, "%s/%02X/%02X",
	SwapDirs[dirn].path,
	filn % SwapDirs[dirn].l1,
	filn / SwapDirs[dirn].l1 % SwapDirs[dirn].l2);
    return fullpath;
}

/* add directory to swap disk */
int
storeAddSwapDisk(const char *path, int size, int l1, int l2, int read_only)
{
    SwapDir *tmp = NULL;
    int i;
    if (strlen(path) > (SQUID_MAXPATHLEN - 32))
	fatal_dump("cache_dir pathname is too long");
    if (SwapDirs == NULL) {
	SwapDirsAllocated = 4;
	SwapDirs = xcalloc(SwapDirsAllocated, sizeof(char *));
    }
    if (SwapDirsAllocated == ncache_dirs) {
	SwapDirsAllocated <<= 1;
	tmp = xcalloc(SwapDirsAllocated, sizeof(char *));
	for (i = 0; i < ncache_dirs; i++)
	    tmp[i] = SwapDirs[i];
	xfree(SwapDirs);
	SwapDirs = tmp;
    }
    SwapDirs[ncache_dirs].path = xstrdup(path);
    SwapDirs[ncache_dirs].max_size = size;
    SwapDirs[ncache_dirs].l1 = l1;
    SwapDirs[ncache_dirs].l2 = l2;
    SwapDirs[ncache_dirs].read_only = read_only;
    SwapDirs[ncache_dirs].map = file_map_create(MAX_FILES_PER_DIR);
    return ++ncache_dirs;
}

static int
storeVerifyOrCreateDir(const char *path)
{
    struct stat sb;
    if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode) == 0)
	return 0;
    safeunlink(path, 0);
    if (mkdir(path, 0777) < 0) {
	if (errno != EEXIST) {
	    sprintf(tmp_error_buf, "Failed to create swap directory %s: %s",
		path,
		xstrerror());
	    fatal(tmp_error_buf);
	}
    }
    debug(20, 1, "Created directory %s\n", path);
    if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode) != 0) {
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
    for (i = 0; i < ncache_dirs; i++) {
	path = SwapDirs[i].path;
	debug(20, 9, "storeVerifySwapDirs: Creating swap space in %s\n", path);
	if (storeVerifyOrCreateDir(path))
	    storeCreateSwapSubDirs(i);
    }
    return directory_created;
}

void
storeCreateSwapSubDirs(int j)
{
    int i, k;
    SwapDir *SD = &SwapDirs[j];
    LOCAL_ARRAY(char, name, MAXPATHLEN);
    for (i = 0; i < SD->l1; i++) {
	sprintf(name, "%s/%02X", SD->path, i);
	debug(20, 1, "Making directories in %s\n", name);
	storeVerifyOrCreateDir(name);
	for (k = 0; k < SD->l2; k++) {
	    sprintf(name, "%s/%02X/%02X", SD->path, i, k);
	    storeVerifyOrCreateDir(name);
	}
    }
}

int
storeMostFreeSwapDir(void)
{
    int most_free = 0;
    int this_free;
    int dirn = 0;
    int i;
    for (i = 0; i < ncache_dirs; i++) {
	this_free = SwapDirs[i].max_size - SwapDirs[i].cur_size;
	if (this_free <= most_free)
	    continue;
	if (SwapDirs[i].read_only)
	    continue;
	most_free = this_free;
	dirn = i;
    }
    return dirn;
}

int
storeDirMapBitTest(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    return file_map_bit_test(SwapDirs[dirn].map, filn);
}

void
storeDirMapBitSet(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    file_map_bit_set(SwapDirs[dirn].map, filn);
    SwapDirs[dirn].suggest++;
}

void
storeDirMapBitReset(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    file_map_bit_reset(SwapDirs[dirn].map, filn);
    if (fn < SwapDirs[dirn].suggest)
	SwapDirs[dirn].suggest = fn;
}

int
storeDirMapAllocate(void)
{
    int dirn = storeMostFreeSwapDir();
    SwapDir *SD = &SwapDirs[dirn];
    int filn = file_map_allocate(SD->map, SD->suggest);
    return (dirn << SWAP_DIR_SHIFT) | (filn & SWAP_FILE_MASK);
}

char *
storeSwapDir(int dirn)
{
    if (dirn < 0 || dirn >= ncache_dirs)
	fatal_dump("storeSwapDir: bad index");
    return SwapDirs[dirn].path;
}

void
storeDirSwapLog(const StoreEntry * e)
{
    LOCAL_ARRAY(char, logmsg, MAX_URL << 1);
    int dirn;
    if (e->swap_file_number < 0)
	fatal_dump("storeDirSwapLog: swap_file_number < 0");
    dirn = e->swap_file_number >> SWAP_DIR_SHIFT;
    /* Note this printf format appears in storeWriteCleanLog() too */
    sprintf(logmsg, "%08x %08x %08x %08x %9d %s\n",
        (int) e->swap_file_number,
        (int) e->timestamp,
        (int) e->expires,
        (int) e->lastmod,
        e->object_len,
        e->url);
    file_write(SwapDirs[dirn].swaplog_fd,
        xstrdup(logmsg),
        strlen(logmsg),
        NULL,
        NULL,
        xfree);
}

static char *
storeDirSwapLogFile(int dirn)
{
    LOCAL_ARRAY(char, path, SQUID_MAXPATHLEN);
    LOCAL_ARRAY(char, digit, 32);
    if (Config.Log.swap) {
	xstrncpy(path, Config.Log.swap, SQUID_MAXPATHLEN - 64);
	strcat(path, ".");
	sprintf(digit, "%02d", dirn);
	strncat(path, digit, 32);
    } else {
	xstrncpy(path, storeSwapDir(dirn), SQUID_MAXPATHLEN - 64);
	strcat(path, "/log");
    }
    return path;
}

void
storeDirOpenSwapLogs(void)
{
    int i;
    int fd;
    char *path;
    SwapDir *SD;
    for (i = 0; i < ncache_dirs; i++) {
	SD = &SwapDirs[i];
	path = storeDirSwapLogFile(i);
	fd = file_open(path, NULL, O_WRONLY | O_CREAT, NULL, NULL);
	if (fd < 0) {
	    debug(50, 1, "%s: %s\n", path, xstrerror());
	    fatal("storeDirOpenSwapLogs: Failed to open swap log.");
	}
	SD->swaplog_fd = fd;
    }
}
