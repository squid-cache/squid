
#include "squid.h"

static char *storeLogTags[] =
{
    "CREATE",
    "SWAPIN",
    "SWAPOUT",
    "RELEASE"
};

static int storelog_fd = -1;

void
storeLog(int tag, const StoreEntry * e)
{
    LOCAL_ARRAY(char, logmsg, MAX_URL << 1);
    MemObject *mem = e->mem_obj;
    struct _http_reply *reply;
    if (storelog_fd < 0)
	return;
    if (mem == NULL)
	return;
    if (mem->log_url == NULL) {
	debug(20, 1) ("storeLog: NULL log_url for %s\n", mem->url);
	storeMemObjectDump(mem);
	mem->log_url = xstrdup(mem->url);
    }
    reply = mem->reply;
    snprintf(logmsg, MAX_URL << 1, "%9d.%03d %-7s %08X %4d %9d %9d %9d %s %d/%d %s %s\n",
	(int) current_time.tv_sec,
	(int) current_time.tv_usec / 1000,
	storeLogTags[tag],
	e->swap_file_number,
	reply->code,
	(int) reply->date,
	(int) reply->last_modified,
	(int) reply->expires,
	reply->content_type[0] ? reply->content_type : "unknown",
	reply->content_length,
	(int) (mem->inmem_hi - mem->reply->hdr_sz),
	RequestMethodStr[mem->method],
	mem->log_url);
    file_write(storelog_fd,
	-1,
	xstrdup(logmsg),
	strlen(logmsg),
	NULL,
	NULL,
	xfree);
}

void
storeLogRotate(void)
{
    char *fname = NULL;
    int i;
    LOCAL_ARRAY(char, from, MAXPATHLEN);
    LOCAL_ARRAY(char, to, MAXPATHLEN);
#ifdef S_ISREG
    struct stat sb;
#endif

    if (storelog_fd > -1) {
	file_close(storelog_fd);
	storelog_fd = -1;
    }
    if ((fname = Config.Log.store) == NULL)
	return;
    if (strcmp(fname, "none") == 0)
	return;
#ifdef S_ISREG
    if (stat(fname, &sb) == 0)
	if (S_ISREG(sb.st_mode) == 0)
	    return;
#endif

    debug(20, 1) ("storeLogRotate: Rotating.\n");

    /* Rotate numbers 0 through N up one */
    for (i = Config.Log.rotateNumber; i > 1;) {
	i--;
	snprintf(from, MAXPATHLEN, "%s.%d", fname, i - 1);
	snprintf(to, MAXPATHLEN, "%s.%d", fname, i);
	rename(from, to);
    }
    /* Rotate the current log to .0 */
    if (Config.Log.rotateNumber > 0) {
	snprintf(to, MAXPATHLEN, "%s.%d", fname, 0);
	rename(fname, to);
    }
    storelog_fd = file_open(fname, O_WRONLY | O_CREAT, NULL, NULL, NULL);
    if (storelog_fd < 0) {
	debug(50, 0) ("storeLogRotate: %s: %s\n", fname, xstrerror());
	debug(20, 1) ("Store logging disabled\n");
    }
}

void
storeLogClose(void)
{
    if (storelog_fd >= 0)
	file_close(storelog_fd);
}

void
storeLogOpen(void)
{
    if (strcmp(Config.Log.store, "none") == 0)
	storelog_fd = -1;
    else
	storelog_fd = file_open(Config.Log.store,
	    O_WRONLY | O_CREAT,
	    NULL,
	    NULL,
	    NULL);
    if (storelog_fd < 0)
	debug(20, 1) ("Store logging disabled\n");
}
