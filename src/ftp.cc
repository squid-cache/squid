/* $Id: ftp.cc,v 1.6 1996/02/29 07:23:11 wessels Exp $ */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>		/* for WNOHANG */
#include <unistd.h>

#include "ansihelp.h"
#include "comm.h"
#include "store.h"
#include "stat.h"
#include "url.h"
#include "mime.h"
#include "fdstat.h"
#include "cache_cf.h"
#include "ttl.h"
#include "util.h"
#include "ftp.h"

#define FTP_DELETE_GAP  (64*1024)

ftpget_thread *FtpgetThread = NULL;
ftpget_thread **FtpgetThreadTailP = &FtpgetThread;

static char ftpASCII[] = "A";
static char ftpBinary[] = "I";

typedef struct _Ftpdata {
    StoreEntry *entry;
    char host[SQUIDHOSTNAMELEN + 1];
    char type_id;
    char request[MAX_URL];
    char *type;
    char *mime_hdr;
    int cpid;
    int ftp_fd;
} FtpData;

extern char *tmp_error_buf;
extern time_t cached_curtime;

static int ftp_open_pipe();
static int ftp_close_pipe();

/* XXX: this does not support FTP on a different port! */
int ftp_url_parser(url, host, request, user, password)
     char *url;
     char *host;
     char *request;
     char *user;
     char *password;
{
    static char atypebuf[MAX_URL];
    static char hostbuf[MAX_URL];
    char *tmp = NULL;
    int t;

    /* initialize everything */
    atypebuf[0] = hostbuf[0] = '\0';
    request[0] = host[0] = user[0] = password[0] = '\0';

    t = sscanf(url, "%[a-zA-Z]://%[^/]%s", atypebuf, hostbuf, request);
    if ((t < 2) ||
	!(!strcasecmp(atypebuf, "ftp") || !strcasecmp(atypebuf, "file"))) {
	return -1;
    } else if (t == 2) {	/* no request */
	strcpy(request, "/");
    } else {
	tmp = url_convert_hex(request);		/* convert %xx to char */
	strncpy(request, tmp, MAX_URL);
	safe_free(tmp);
    }

    /* url address format is something like this:
     * [ userid [ : password ] @ ] host 
     * or possibly even
     * [ [ userid ] [ : [ password ] ] @ ] host
     * 
     * So we must try to make sense of it.  */

    /* XXX: this only support [user:passwd@]host */
    t = sscanf(hostbuf, "%[^:]:%[^@]@%s", user, password, host);
    if (t < 3) {
	strcpy(host, user);	/* no login/passwd information */
	strcpy(user, "anonymous");
	strcpy(password, "harvest@");
    }
    /* we need to convert user and password for URL encodings */
    tmp = url_convert_hex(user);
    strcpy(user, tmp);
    safe_free(tmp);

    tmp = url_convert_hex(password);
    strcpy(password, tmp);
    safe_free(tmp);

    return 0;
}

int ftpCachable(url, type, mime_hdr)
     char *url;
     char *type;
     char *mime_hdr;
{
    stoplist *p = NULL;

    /* scan stop list */
    p = ftp_stoplist;
    while (p) {
	if (strstr(url, p->key))
	    return 0;
	p = p->next;
    }

    /* else cachable */
    return 1;
}

/* This will be called when socket lifetime is expired. */
void ftpLifetimeExpire(fd, data)
     int fd;
     FtpData *data;
{
    StoreEntry *entry = NULL;
    entry = data->entry;
    debug(4, "ftpLifeTimeExpire: FD %d: <URL:%s>\n", fd, entry->url);
    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	entry->url,
	entry->url,
	"FTP",
	210,
	"Transaction Timeout",
	"The Network/Remote site may be down or too slow.  Try again later.",
	SQUID_VERSION,
	comm_hostname());
    storeAbort(entry, tmp_error_buf);
    ftp_close_pipe(data->ftp_fd, data->cpid);
    comm_close(fd);
#ifdef LOG_ERRORS
    CacheInfo->log_append(CacheInfo,
	entry->url,
	"0.0.0.0",
	entry->mem_obj->e_current_len,
	"ERR_210",		/* FTP LIFETIME EXPIRE */
	data->type ? data->type : "NULL");
#endif
    safe_free(data);
}



/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
int ftpReadReply(fd, data)
     int fd;
     FtpData *data;
{
    static char buf[4096];
    int len;
    int clen;
    int off;
    StoreEntry *entry = NULL;

    entry = data->entry;
    if (entry->flag & DELETE_BEHIND) {
	if (storeClientWaiting(entry)) {
	    /* check if we want to defer reading */
	    clen = entry->mem_obj->e_current_len;
	    off = entry->mem_obj->e_lowest_offset;
	    if ((clen - off) > FTP_DELETE_GAP) {
		debug(3, "ftpReadReply: Read deferred for Object: %s\n",
		    entry->key);
		debug(3, "                Current Gap: %d bytes\n",
		    clen - off);

		/* reschedule, so it will automatically be reactivated when
		 * Gap is big enough. */
		comm_set_select_handler(fd,
		    COMM_SELECT_READ,
		    (PF) ftpReadReply,
		    (caddr_t) data);
		return 0;
	    }
	} else {
	    /* we can terminate connection right now */
	    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
		entry->url,
		entry->url,
		"FTP",
		319,
		"No Client",
		"All Clients went away before tranmission is complete and object is too big to cache.",
		SQUID_VERSION,
		comm_hostname());
	    storeAbort(entry, tmp_error_buf);
	    ftp_close_pipe(data->ftp_fd, data->cpid);
	    comm_close(fd);
#ifdef LOG_ERRORS
	    CacheInfo->log_append(CacheInfo,
		entry->url,
		"0.0.0.0",
		entry->mem_obj->e_current_len,
		"ERR_319",	/* FTP NO CLIENTS, BIG OBJECT */
		data->type ? data->type : "NULL");
#endif
	    safe_free(data);
	    return 0;
	}
    }
    len = read(fd, buf, 4096);
    debug(5, "ftpReadReply FD %d, len=%d\n", fd, len);

    if (len < 0 || ((len == 0) && (entry->mem_obj->e_current_len == 0))) {
	if (len < 0)
	    debug(1, "ftpReadReply - error reading: %s\n", xstrerror());
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "FTP",
	    305,
	    "Read Error.",
	    "Network/Remote Site is down.  Try again later.",
	    SQUID_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
	ftp_close_pipe(data->ftp_fd, data->cpid);
	comm_close(fd);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    entry->mem_obj->e_current_len,
	    "ERR_305",		/* FTP READ ERROR */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	/* If ftpget failed, arrange so the object gets ejected and
	 * doesn't get to disk. */
	if (ftp_close_pipe(data->ftp_fd, data->cpid) != 0) {
	    entry->expires = cached_curtime + getNegativeTTL();
	    BIT_RESET(entry->flag, CACHABLE);
	    BIT_SET(entry->flag, RELEASE_REQUEST);
	} else if (!(entry->flag & DELETE_BEHIND)) {
	    entry->expires = cached_curtime + ttlSet(entry);
	}
	/* update fdstat and fdtable */
	comm_close(fd);
	storeComplete(entry);
	safe_free(data);
    } else if (((entry->mem_obj->e_current_len + len) > getFtpMax()) &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);

	storeAppend(entry, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) ftpReadReply,
	    (caddr_t) data);

    } else if (entry->flag & CLIENT_ABORT_REQUEST) {
	/* append the last bit of info we get */
	storeAppend(entry, buf, len);
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "FTP",
	    307,
	    "Client Aborted",
	    "Client(s) dropped connection before transmission is complete.\nObject fetching is aborted.\n",
	    SQUID_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
	ftp_close_pipe(data->ftp_fd, data->cpid);
	comm_close(fd);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    entry->mem_obj->e_current_len,
	    "ERR_307",		/* FTP CLIENT ABORT */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
    } else {
	storeAppend(entry, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) ftpReadReply,
	    (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) ftpLifetimeExpire,
	    (caddr_t) data,
	    getReadTimeout());
    }
    return 0;
}


int ftpStart(unusedfd, url, entry)
     int unusedfd;
     char *url;
     StoreEntry *entry;
{
    static char user[MAX_URL];
    static char password[MAX_URL];
    FtpData *data = NULL;

    debug(3, "FtpStart: FD %d <URL:%s>\n", unusedfd, url);

    data = (FtpData *) xcalloc(1, sizeof(FtpData));
    data->entry = entry;

    /* Parse url. */
    user[0] = password[0] = '\0';
    if (ftp_url_parser(url, data->host, data->request, user, password)) {
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "FTP",
	    309,
	    "Invalid URL syntax: Cannot parse.",
	    "Please contact your system manager for further help.",
	    SQUID_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    entry->mem_obj->e_current_len,
	    "ERR_309",		/* FTP INVALID URL */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
	return COMM_ERROR;
    }
    debug(5, "FtpStart - host:%s, request:%s, user:%s, passwd:%s\n",
	data->host, data->request, user, password);

    /* Create socket. */
    data->ftp_fd = ftp_open_pipe(getFtpProgram(),
	data->host,
	data->request,
	user,
	password,
	"r",
	&(data->cpid),
	getFtpOptions());

    if (data->ftp_fd < 0) {
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "FTP",
	    308,
	    "Cannot connect to FTP slave process",
	    "Please contact your system manager for further help.",
	    SQUID_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    entry->mem_obj->e_current_len,
	    "ERR_308",		/* FTP FTPGET FAIL */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
	return COMM_ERROR;
    }
    /* Pipe created ok */

    debug(5, "startftp - conn %d EINPROGRESS\n", data->ftp_fd);

    fdstat_open(data->ftp_fd, Pipe);
    commSetNonBlocking(data->ftp_fd);
    (void) fd_note(data->ftp_fd, entry->url);

    /* Install connection complete handler. */
    fd_note(data->ftp_fd, entry->url);
    comm_set_select_handler(data->ftp_fd, COMM_SELECT_WRITE, 0, 0);
    comm_set_fd_lifetime(data->ftp_fd, getClientLifetime());
    comm_set_select_handler(data->ftp_fd,
	COMM_SELECT_LIFETIME,
	(PF) ftpLifetimeExpire,
	(caddr_t) data);
    comm_set_select_handler(data->ftp_fd,
	COMM_SELECT_READ,
	(PF) ftpReadReply,
	(caddr_t) data);
    comm_set_select_handler_plus_timeout(data->ftp_fd,
	COMM_SELECT_TIMEOUT,
	(PF) ftpLifetimeExpire,
	(caddr_t) data, getReadTimeout());
    return COMM_OK;
}

/*
 *  ftp_open_pipe - This opens a pipe to the ftpget command.
 *  It currently supports read-only pipes and hardcoded args.  The child
 *  process only has stdin from /dev/null, stdout to the pipe,
 *  and stderr inherited from the parent.  cpid is set to the
 *  pid of the child process or to -1 on error.  Returns a read-only
 *  file descriptor to the read end of the pipe, or -1 on error.  
 *
 *  Allows process to make many ftp_open_pipe() calls.  -DH
 */
static int ftp_open_pipe(p1, p2, p3, p4, p5, type, cpid, opts)
     char *p1, *p2, *p3, *p4, *p5, *type, *opts;
     int *cpid;
{
    int pfd[2];
    int pid;
    int fd;
    char *transfer = NULL;
    ftpget_thread *thread = NULL;
    static char tbuf[64];
    int got_timeout = 0;
    int got_negttl = 0;
    int argc;
    char *argv[64];
    static char *w_space = "\n\t ";
    char *s = NULL;

    if (p3[strlen(p3) - 1] == '/')
	transfer = ftpASCII;
    else {
	char *ext;
	ext_table_entry *e;

	if ((ext = strrchr(p3, '.')) != NULL) {
	    ext++;
	    transfer = ((e = mime_ext_to_type(ext)) &&
		strncmp(e->mime_type, "text", 4) == 0) ? ftpASCII :
		ftpBinary;
	} else
	    transfer = ftpBinary;
    }

    *cpid = -1;			/* initialize first */

    if (type == NULL || strcmp(type, "r") != 0) {
	debug(0, "ftp_open_pipe: type %s unsupported.\n",
	    type ? type : "(null)");
	return (-1);		/* unsupported */
    }
    pfd[0] = pfd[1] = -1;	/* For debugging */
    if (pipe(pfd) < 0) {
	debug(0, "ftp_open_pipe: pipe: %s\n", xstrerror());
	if (pfd[0] > -1)
	    close(pfd[0]);
	if (pfd[1] > -1)
	    close(pfd[1]);
	return (-1);
    }
    if ((pid = fork()) < 0) {
	debug(0, "ftp_open_pipe: fork: %s\n", xstrerror());
	close(pfd[0]);
	close(pfd[1]);
	return (-1);
    }
    if (pid != 0) {		/* parent */
	*cpid = pid;		/* pass child pid */
	(void) close(pfd[1]);	/* close the write pipe */
	fcntl(pfd[0], F_SETFD, 1);	/* set close-on-exec */
	thread = (ftpget_thread *) xcalloc(1, sizeof(ftpget_thread));
	thread->pid = pid;
	thread->fd = pfd[0];
	*FtpgetThreadTailP = thread;
	FtpgetThreadTailP = (&(thread->next));
	return (pfd[0]);	/* return read FD */
    }
    /* child */
    close(0);
    if (open("/dev/null", O_RDONLY, 0) < 0)
	debug(0, "ftp_open_pipe: /dev/null: %s\n", xstrerror());
    if (dup2(pfd[1], 1) < 0) {	/* stdout -> write pipe */
	debug(0, "ftp_open_pipe: dup2(%d,%d): %s\n", pfd[1], 1, xstrerror());
	_exit(1);
    }
    /* stderr is inherited */

    /* close all file desc, and make sure we close the read pipe */
    for (fd = 3; fd < fdstat_biggest_fd(); fd++)
	(void) close(fd);
    (void) close(pfd[0]);
    (void) close(pfd[1]);

    /*
     *  Remove leading slash from FTP url-path so that we can
     *  handle ftp://user:pw@host/path objects where path and /path
     *  are quite different.         -DW
     */
    if (!strcmp(p3, "/"))
	*p3 = '.';
    if (*p3 == '/')
	p3++;


    /*
     *  Run the ftpget command:
     *   p1 is the ftpget program, need execlp() to use PATH
     *   p2 is the remote host
     *   p3 is the remote file
     *   transfer is "A" for ASCII and "I" for binary transfer
     *   p4 is the username
     *   p5 is the password
     */

    argc = 0;
    argv[argc++] = xstrdup(p1);
    for (s = strtok(opts, w_space); s; s = strtok(NULL, w_space)) {
	argv[argc++] = xstrdup(s);
	if (!strncmp(s, "-t", 2))
	    got_timeout = 1;
	if (!strncmp(s, "-n", 2))
	    got_negttl = 1;
    }
    if (!got_timeout) {
	argv[argc++] = xstrdup("-t");
	sprintf(tbuf, "%d", getReadTimeout());
	argv[argc++] = xstrdup(tbuf);
    }
    if (!got_negttl) {
	argv[argc++] = xstrdup("-n");
	sprintf(tbuf, "%d", getNegativeTTL());
	argv[argc++] = xstrdup(tbuf);
    }
    argv[argc++] = xstrdup("-h");	/* httpify */
    argv[argc++] = xstrdup("-");	/* stdout */
    argv[argc++] = xstrdup(p2);	/* hostname */
    argv[argc++] = xstrdup(p3);	/* pathname */
    argv[argc++] = xstrdup(transfer);	/* A or I */
    argv[argc++] = xstrdup(p4);	/* username */
    argv[argc++] = xstrdup(p5);	/* password */
    argv[argc++] = NULL;	/* terminate */
    execvp(p1, argv);
    perror(p1);
    _exit(1);
    return (0); /* NOTREACHED */
}

/*
 *  ftp_close_pipe - closes the pipe opened by ftp_open_pipe.  
 *  Non-blocking.  -DH
 *
 *  Return 0 if ftpget exits successfully, or 1 upon failure.
 */
static int ftp_close_pipe(fd, cpid)
     int fd;
     int cpid;
{
    int status;
    int ret;
    ftpget_thread *t = NULL;
    ftpget_thread **T = NULL;
    ftpget_thread *match = NULL;
    ftpget_thread *next = NULL;

    (void) close(fd);		/* close stdio ptr -- should generate SIGCHLD */

    /*
     * Look through the ftpget-thread list for an entry with
     * the same pid and FILE ptr.  These entries are added in
     * ftp_open_pipe()
     */
    for (t = FtpgetThread; t; t = t->next) {
	if (t->pid == cpid && t->fd == fd) {
	    match = t;
	    break;
	}
    }

    /*
     * If the matched entry is in state FTPGET_THREAD_WAITED
     * then the child process was wait()'ed for in the
     * generic SIGCHLD handler.  That handler will have
     * filled in status and return values
     */
    if (match && match->state == FTPGET_THREAD_WAITED) {
	ret = match->wait_retval;
	status = match->status;
	debug(3, "Check Thread: Match found, wait_retval=%d  status=0x%x\n",
	    ret, status);
    } else {
	/* No match found, do the wait() ourselves */
	ret = waitpid(cpid, &status, WNOHANG);	/* non-blocking wait */
    }

    if (match) {
	/* remove match from the linked list */
	for (T = &FtpgetThread, t = FtpgetThread; t; t = next) {
	    next = t->next;
	    if (t == match) {
		*T = t->next;
		xfree(t);
	    } else {
		T = &(t->next);
	    }
	}
	FtpgetThreadTailP = T;
    }
    if (ret == 0)
	return 0;
    if (ret < 0) {
	return 1;
    }
    if (ret != cpid) {
	return 1;
    }
    if (WIFSIGNALED(status)) {
	debug(0, "%s exited due to signal %d\n",
	    getFtpProgram(), WTERMSIG(status));
	return 1;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) > 0) {
	if (WEXITSTATUS(status) < 10) {
	    /* SOFT ERROR -- DONT CACHE */
	    debug(1, "%s returned exit status %d\n",
		getFtpProgram(), WEXITSTATUS(status));
	    return 1;
	} else {
	    /* HARD ERROR -- DO CACHE */
	    debug(5, "%s returned exit status %d\n",
		getFtpProgram(), WEXITSTATUS(status));
	    return 0;
	}
    }
    return 0;
}
