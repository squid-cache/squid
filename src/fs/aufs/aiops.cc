/*
 * $Id: aiops.cc,v 1.7 2001/01/12 00:37:32 wessels Exp $
 *
 * DEBUG: section 43    AIOPS
 * AUTHOR: Stewart Forster <slf@connect.com.au>
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "store_asyncufs.h"

#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<pthread.h>
#include	<errno.h>
#include	<dirent.h>
#include	<signal.h>
#if HAVE_SCHED_H
#include	<sched.h>
#endif

#define RIDICULOUS_LENGTH	4096

enum _aio_thread_status {
    _THREAD_STARTING = 0,
    _THREAD_WAITING,
    _THREAD_BUSY,
    _THREAD_FAILED,
    _THREAD_DONE
};

enum _aio_request_type {
    _AIO_OP_NONE = 0,
    _AIO_OP_OPEN,
    _AIO_OP_READ,
    _AIO_OP_WRITE,
    _AIO_OP_CLOSE,
    _AIO_OP_UNLINK,
    _AIO_OP_TRUNCATE,
    _AIO_OP_OPENDIR,
    _AIO_OP_STAT
};

typedef struct aio_request_t {
    struct aio_request_t *next;
    enum _aio_request_type request_type;
    int cancelled;
    char *path;
    int oflag;
    mode_t mode;
    int fd;
    char *bufferp;
    char *tmpbufp;
    int buflen;
    off_t offset;
    int whence;
    int ret;
    int err;
    struct stat *tmpstatp;
    struct stat *statp;
    aio_result_t *resultp;
} aio_request_t;

typedef struct aio_request_queue_t {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    aio_request_t *volatile head;
    aio_request_t *volatile *volatile tailp;
    unsigned long requests;
    unsigned long blocked;	/* main failed to lock the queue */
} aio_request_queue_t;

typedef struct aio_thread_t aio_thread_t;
struct aio_thread_t {
    aio_thread_t *next;
    pthread_t thread;
    enum _aio_thread_status status;
    struct aio_request_t *current_req;
    unsigned long requests;
};

int aio_cancel(aio_result_t *);
int aio_open(const char *, int, mode_t, aio_result_t *);
int aio_read(int, char *, int, off_t, int, aio_result_t *);
int aio_write(int, char *, int, off_t, int, aio_result_t *);
int aio_close(int, aio_result_t *);
int aio_unlink(const char *, aio_result_t *);
int aio_truncate(const char *, off_t length, aio_result_t *);
int aio_opendir(const char *, aio_result_t *);
aio_result_t *aio_poll_done();
int aio_sync(void);

static void aio_init(void);
static void aio_queue_request(aio_request_t *);
static void aio_cleanup_request(aio_request_t *);
static void *aio_thread_loop(void *);
static void aio_do_open(aio_request_t *);
static void aio_do_read(aio_request_t *);
static void aio_do_write(aio_request_t *);
static void aio_do_close(aio_request_t *);
static void aio_do_stat(aio_request_t *);
static void aio_do_unlink(aio_request_t *);
static void aio_do_truncate(aio_request_t *);
#if AIO_OPENDIR
static void *aio_do_opendir(aio_request_t *);
#endif
static void aio_debug(aio_request_t *);
static void aio_poll_queues(void);

static aio_thread_t *threads = NULL;
static int aio_initialised = 0;


#define AIO_LARGE_BUFS  16384
#define AIO_MEDIUM_BUFS	AIO_LARGE_BUFS >> 1
#define AIO_SMALL_BUFS	AIO_LARGE_BUFS >> 2
#define AIO_TINY_BUFS	AIO_LARGE_BUFS >> 3
#define AIO_MICRO_BUFS	128

static MemPool *aio_large_bufs = NULL;	/* 16K */
static MemPool *aio_medium_bufs = NULL;		/* 8K */
static MemPool *aio_small_bufs = NULL;	/* 4K */
static MemPool *aio_tiny_bufs = NULL;	/* 2K */
static MemPool *aio_micro_bufs = NULL;	/* 128K */

static int request_queue_len = 0;
static MemPool *aio_request_pool = NULL;
static MemPool *aio_thread_pool = NULL;
static aio_request_queue_t request_queue;
static struct {
    aio_request_t *head, **tailp;
} request_queue2 = {

    NULL, &request_queue2.head
};
static aio_request_queue_t done_queue;
static struct {
    aio_request_t *head, **tailp;
} done_requests = {

    NULL, &done_requests.head
};
static pthread_attr_t globattr;
static struct sched_param globsched;
static pthread_t main_thread;

static MemPool *
aio_get_pool(int size)
{
    MemPool *p;
    if (size <= AIO_LARGE_BUFS) {
	if (size <= AIO_MICRO_BUFS)
	    p = aio_micro_bufs;
	else if (size <= AIO_TINY_BUFS)
	    p = aio_tiny_bufs;
	else if (size <= AIO_SMALL_BUFS)
	    p = aio_small_bufs;
	else if (size <= AIO_MEDIUM_BUFS)
	    p = aio_medium_bufs;
	else
	    p = aio_large_bufs;
    } else
	p = NULL;
    return p;
}

static void *
aio_xmalloc(int size)
{
    void *p;
    MemPool *pool;

    if ((pool = aio_get_pool(size)) != NULL) {
	p = memPoolAlloc(pool);
    } else
	p = xmalloc(size);

    return p;
}

static char *
aio_xstrdup(const char *str)
{
    char *p;
    int len = strlen(str) + 1;

    p = aio_xmalloc(len);
    strncpy(p, str, len);

    return p;
}

static void
aio_xfree(void *p, int size)
{
    MemPool *pool;

    if ((pool = aio_get_pool(size)) != NULL) {
	memPoolFree(pool, p);
    } else
	xfree(p);
}

static void
aio_xstrfree(char *str)
{
    MemPool *pool;
    int len = strlen(str) + 1;

    if ((pool = aio_get_pool(len)) != NULL) {
	memPoolFree(pool, str);
    } else
	xfree(str);
}

static void
aio_init(void)
{
    int i;
    aio_thread_t *threadp;

    if (aio_initialised)
	return;

    pthread_attr_init(&globattr);
#if HAVE_PTHREAD_ATTR_SETSCOPE
    pthread_attr_setscope(&globattr, PTHREAD_SCOPE_SYSTEM);
#endif
    globsched.sched_priority = 1;
    main_thread = pthread_self();
#if HAVE_PTHREAD_SETSCHEDPARAM
    pthread_setschedparam(main_thread, SCHED_OTHER, &globsched);
#endif
    globsched.sched_priority = 2;
#if HAVE_PTHREAD_ATTR_SETSCHEDPARAM
    pthread_attr_setschedparam(&globattr, &globsched);
#endif

    /* Initialize request queue */
    if (pthread_mutex_init(&(request_queue.mutex), NULL))
	fatal("Failed to create mutex");
    if (pthread_cond_init(&(request_queue.cond), NULL))
	fatal("Failed to create condition variable");
    request_queue.head = NULL;
    request_queue.tailp = &request_queue.head;
    request_queue.requests = 0;
    request_queue.blocked = 0;

    /* Initialize done queue */
    if (pthread_mutex_init(&(done_queue.mutex), NULL))
	fatal("Failed to create mutex");
    if (pthread_cond_init(&(done_queue.cond), NULL))
	fatal("Failed to create condition variable");
    done_queue.head = NULL;
    done_queue.tailp = &done_queue.head;
    done_queue.requests = 0;
    done_queue.blocked = 0;

    /* Create threads and get them to sit in their wait loop */
    aio_thread_pool = memPoolCreate("aio_thread", sizeof(aio_thread_t));
    for (i = 0; i < NUMTHREADS; i++) {
	threadp = memPoolAlloc(aio_thread_pool);
	threadp->status = _THREAD_STARTING;
	threadp->current_req = NULL;
	threadp->requests = 0;
	threadp->next = threads;
	threads = threadp;
	if (pthread_create(&threadp->thread, &globattr, aio_thread_loop, threadp)) {
	    fprintf(stderr, "Thread creation failed\n");
	    threadp->status = _THREAD_FAILED;
	    continue;
	}
    }

    /* Create request pool */
    aio_request_pool = memPoolCreate("aio_request", sizeof(aio_request_t));
    aio_large_bufs = memPoolCreate("aio_large_bufs", AIO_LARGE_BUFS);
    aio_medium_bufs = memPoolCreate("aio_medium_bufs", AIO_MEDIUM_BUFS);
    aio_small_bufs = memPoolCreate("aio_small_bufs", AIO_SMALL_BUFS);
    aio_tiny_bufs = memPoolCreate("aio_tiny_bufs", AIO_TINY_BUFS);
    aio_micro_bufs = memPoolCreate("aio_micro_bufs", AIO_MICRO_BUFS);

    aio_initialised = 1;
}


static void *
aio_thread_loop(void *ptr)
{
    aio_thread_t *threadp = ptr;
    aio_request_t *request;
    sigset_t new;

    /*
     * Make sure to ignore signals which may possibly get sent to
     * the parent squid thread.  Causes havoc with mutex's and
     * condition waits otherwise
     */

    sigemptyset(&new);
    sigaddset(&new, SIGPIPE);
    sigaddset(&new, SIGCHLD);
#ifdef _SQUID_LINUX_THREADS_
    sigaddset(&new, SIGQUIT);
    sigaddset(&new, SIGTRAP);
#else
    sigaddset(&new, SIGUSR1);
    sigaddset(&new, SIGUSR2);
#endif
    sigaddset(&new, SIGHUP);
    sigaddset(&new, SIGTERM);
    sigaddset(&new, SIGINT);
    sigaddset(&new, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &new, NULL);

    while (1) {
	threadp->current_req = request = NULL;
	request = NULL;
	/* Get a request to process */
	threadp->status = _THREAD_WAITING;
	pthread_mutex_lock(&request_queue.mutex);
	while (!request_queue.head) {
	    pthread_cond_wait(&request_queue.cond, &request_queue.mutex);
	}
	request = request_queue.head;
	if (request)
	    request_queue.head = request->next;
	if (!request_queue.head)
	    request_queue.tailp = &request_queue.head;
	pthread_mutex_unlock(&request_queue.mutex);
	/* process the request */
	threadp->status = _THREAD_BUSY;
	request->next = NULL;
	threadp->current_req = request;
	errno = 0;
	if (!request->cancelled) {
	    switch (request->request_type) {
	    case _AIO_OP_OPEN:
		aio_do_open(request);
		break;
	    case _AIO_OP_READ:
		aio_do_read(request);
		break;
	    case _AIO_OP_WRITE:
		aio_do_write(request);
		break;
	    case _AIO_OP_CLOSE:
		aio_do_close(request);
		break;
	    case _AIO_OP_UNLINK:
		aio_do_unlink(request);
		break;
	    case _AIO_OP_TRUNCATE:
		aio_do_truncate(request);
		break;
#if AIO_OPENDIR			/* Opendir not implemented yet */
	    case _AIO_OP_OPENDIR:
		aio_do_opendir(request);
		break;
#endif
	    case _AIO_OP_STAT:
		aio_do_stat(request);
		break;
	    default:
		request->ret = -1;
		request->err = EINVAL;
		break;
	    }
	} else {		/* cancelled */
	    request->ret = -1;
	    request->err = EINTR;
	}
	threadp->status = _THREAD_DONE;
	/* put the request in the done queue */
	pthread_mutex_lock(&done_queue.mutex);
	*done_queue.tailp = request;
	done_queue.tailp = &request->next;
	pthread_mutex_unlock(&done_queue.mutex);
	threadp->requests++;
    }				/* while forever */
    return NULL;
}				/* aio_thread_loop */

static void
aio_queue_request(aio_request_t * request)
{
    static int high_start = 0;
    debug(41, 9) ("aio_queue_request: %p type=%d result=%p\n",
	request, request->request_type, request->resultp);
    /* Mark it as not executed (failing result, no error) */
    request->ret = -1;
    request->err = 0;
    /* Internal housekeeping */
    request_queue_len += 1;
    request->resultp->_data = request;
    /* Play some tricks with the request_queue2 queue */
    request->next = NULL;
    if (!request_queue2.head) {
	if (pthread_mutex_trylock(&request_queue.mutex) == 0) {
	    /* Normal path */
	    *request_queue.tailp = request;
	    request_queue.tailp = &request->next;
	    pthread_cond_signal(&request_queue.cond);
	    pthread_mutex_unlock(&request_queue.mutex);
	} else {
	    /* Oops, the request queue is blocked, use request_queue2 */
	    *request_queue2.tailp = request;
	    request_queue2.tailp = &request->next;
	}
    } else {
	/* Secondary path. We have blocked requests to deal with */
	/* add the request to the chain */
	*request_queue2.tailp = request;
	if (pthread_mutex_trylock(&request_queue.mutex) == 0) {
	    /* Ok, the queue is no longer blocked */
	    *request_queue.tailp = request_queue2.head;
	    request_queue.tailp = &request->next;
	    pthread_cond_signal(&request_queue.cond);
	    pthread_mutex_unlock(&request_queue.mutex);
	    request_queue2.head = NULL;
	    request_queue2.tailp = &request_queue2.head;
	} else {
	    /* still blocked, bump the blocked request chain */
	    request_queue2.tailp = &request->next;
	}
    }
    if (request_queue2.head) {
	static int filter = 0;
	static int filter_limit = 8;
	if (++filter >= filter_limit) {
	    filter_limit += filter;
	    filter = 0;
	    debug(43, 1) ("aio_queue_request: WARNING - Queue congestion\n");
	}
    }
    /* Warn if out of threads */
    if (request_queue_len > MAGIC1) {
	static int last_warn = 0;
	static int queue_high, queue_low;
	if (high_start == 0) {
	    high_start = squid_curtime;
	    queue_high = request_queue_len;
	    queue_low = request_queue_len;
	}
	if (request_queue_len > queue_high)
	    queue_high = request_queue_len;
	if (request_queue_len < queue_low)
	    queue_low = request_queue_len;
	if (squid_curtime >= (last_warn + 15) &&
	    squid_curtime >= (high_start + 5)) {
	    debug(43, 1) ("aio_queue_request: WARNING - Disk I/O overloading\n");
	    if (squid_curtime >= (high_start + 15))
		debug(43, 1) ("aio_queue_request: Queue Length: current=%d, high=%d, low=%d, duration=%d\n",
		    request_queue_len, queue_high, queue_low, squid_curtime - high_start);
	    last_warn = squid_curtime;
	}
    } else {
	high_start = 0;
    }
    /* Warn if seriously overloaded */
    if (request_queue_len > RIDICULOUS_LENGTH) {
	debug(43, 0) ("aio_queue_request: Async request queue growing uncontrollably!\n");
	debug(43, 0) ("aio_queue_request: Syncing pending I/O operations.. (blocking)\n");
	aio_sync();
	debug(43, 0) ("aio_queue_request: Synced\n");
    }
}				/* aio_queue_request */

static void
aio_cleanup_request(aio_request_t * requestp)
{
    aio_result_t *resultp = requestp->resultp;
    int cancelled = requestp->cancelled;

    /* Free allocated structures and copy data back to user space if the */
    /* request hasn't been cancelled */
    switch (requestp->request_type) {
    case _AIO_OP_STAT:
	if (!cancelled && requestp->ret == 0)
	    xmemcpy(requestp->statp, requestp->tmpstatp, sizeof(struct stat));
	aio_xfree(requestp->tmpstatp, sizeof(struct stat));
	aio_xstrfree(requestp->path);
	break;
    case _AIO_OP_OPEN:
	if (cancelled && requestp->ret >= 0)
	    /* The open() was cancelled but completed */
	    close(requestp->ret);
	aio_xstrfree(requestp->path);
	break;
    case _AIO_OP_CLOSE:
	if (cancelled && requestp->ret < 0)
	    /* The close() was cancelled and never got executed */
	    close(requestp->fd);
	break;
    case _AIO_OP_UNLINK:
    case _AIO_OP_TRUNCATE:
    case _AIO_OP_OPENDIR:
	aio_xstrfree(requestp->path);
	break;
    case _AIO_OP_READ:
	if (!cancelled && requestp->ret > 0)
	    xmemcpy(requestp->bufferp, requestp->tmpbufp, requestp->ret);
	aio_xfree(requestp->tmpbufp, requestp->buflen);
	break;
    case _AIO_OP_WRITE:
	aio_xfree(requestp->tmpbufp, requestp->buflen);
	break;
    default:
	break;
    }
    if (resultp != NULL && !cancelled) {
	resultp->aio_return = requestp->ret;
	resultp->aio_errno = requestp->err;
    }
    memPoolFree(aio_request_pool, requestp);
}				/* aio_cleanup_request */


int
aio_cancel(aio_result_t * resultp)
{
    aio_request_t *request = resultp->_data;

    if (request && request->resultp == resultp) {
	debug(41, 9) ("aio_cancel: %p type=%d result=%p\n",
	    request, request->request_type, request->resultp);
	request->cancelled = 1;
	request->resultp = NULL;
	resultp->_data = NULL;
	return 0;
    }
    return 1;
}				/* aio_cancel */


int
aio_open(const char *path, int oflag, mode_t mode, aio_result_t * resultp)
{
    aio_request_t *requestp;

    if (!aio_initialised)
	aio_init();
    requestp = memPoolAlloc(aio_request_pool);
    requestp->path = (char *) aio_xstrdup(path);
    requestp->oflag = oflag;
    requestp->mode = mode;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_OPEN;
    requestp->cancelled = 0;

    aio_queue_request(requestp);
    return 0;
}


static void
aio_do_open(aio_request_t * requestp)
{
    requestp->ret = open(requestp->path, requestp->oflag, requestp->mode);
    requestp->err = errno;
}


int
aio_read(int fd, char *bufp, int bufs, off_t offset, int whence, aio_result_t * resultp)
{
    aio_request_t *requestp;

    if (!aio_initialised)
	aio_init();
    requestp = memPoolAlloc(aio_request_pool);
    requestp->fd = fd;
    requestp->bufferp = bufp;
    requestp->tmpbufp = (char *) aio_xmalloc(bufs);
    requestp->buflen = bufs;
    requestp->offset = offset;
    requestp->whence = whence;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_READ;
    requestp->cancelled = 0;

    aio_queue_request(requestp);
    return 0;
}


static void
aio_do_read(aio_request_t * requestp)
{
    lseek(requestp->fd, requestp->offset, requestp->whence);
    requestp->ret = read(requestp->fd, requestp->tmpbufp, requestp->buflen);
    requestp->err = errno;
}


int
aio_write(int fd, char *bufp, int bufs, off_t offset, int whence, aio_result_t * resultp)
{
    aio_request_t *requestp;

    if (!aio_initialised)
	aio_init();
    requestp = memPoolAlloc(aio_request_pool);
    requestp->fd = fd;
    requestp->tmpbufp = (char *) aio_xmalloc(bufs);
    xmemcpy(requestp->tmpbufp, bufp, bufs);
    requestp->buflen = bufs;
    requestp->offset = offset;
    requestp->whence = whence;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_WRITE;
    requestp->cancelled = 0;

    aio_queue_request(requestp);
    return 0;
}


static void
aio_do_write(aio_request_t * requestp)
{
    requestp->ret = write(requestp->fd, requestp->tmpbufp, requestp->buflen);
    requestp->err = errno;
}


int
aio_close(int fd, aio_result_t * resultp)
{
    aio_request_t *requestp;

    if (!aio_initialised)
	aio_init();
    requestp = memPoolAlloc(aio_request_pool);
    requestp->fd = fd;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_CLOSE;
    requestp->cancelled = 0;

    aio_queue_request(requestp);
    return 0;
}


static void
aio_do_close(aio_request_t * requestp)
{
    requestp->ret = close(requestp->fd);
    requestp->err = errno;
}


int
aio_stat(const char *path, struct stat *sb, aio_result_t * resultp)
{
    aio_request_t *requestp;

    if (!aio_initialised)
	aio_init();
    requestp = memPoolAlloc(aio_request_pool);
    requestp->path = (char *) aio_xstrdup(path);
    requestp->statp = sb;
    requestp->tmpstatp = (struct stat *) aio_xmalloc(sizeof(struct stat));
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_STAT;
    requestp->cancelled = 0;

    aio_queue_request(requestp);
    return 0;
}


static void
aio_do_stat(aio_request_t * requestp)
{
    requestp->ret = stat(requestp->path, requestp->tmpstatp);
    requestp->err = errno;
}


int
aio_unlink(const char *path, aio_result_t * resultp)
{
    aio_request_t *requestp;

    if (!aio_initialised)
	aio_init();
    requestp = memPoolAlloc(aio_request_pool);
    requestp->path = aio_xstrdup(path);
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_UNLINK;
    requestp->cancelled = 0;

    aio_queue_request(requestp);
    return 0;
}


static void
aio_do_unlink(aio_request_t * requestp)
{
    requestp->ret = unlink(requestp->path);
    requestp->err = errno;
}

int
aio_truncate(const char *path, off_t length, aio_result_t * resultp)
{
    aio_request_t *requestp;

    if (!aio_initialised)
	aio_init();
    requestp = memPoolAlloc(aio_request_pool);
    requestp->path = (char *) aio_xstrdup(path);
    requestp->offset = length;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_TRUNCATE;
    requestp->cancelled = 0;

    aio_queue_request(requestp);
    return 0;
}


static void
aio_do_truncate(aio_request_t * requestp)
{
    requestp->ret = truncate(requestp->path, requestp->offset);
    requestp->err = errno;
}


#if AIO_OPENDIR
/* XXX aio_opendir NOT implemented yet.. */

int
aio_opendir(const char *path, aio_result_t * resultp)
{
    aio_request_t *requestp;
    int len;

    if (!aio_initialised)
	aio_init();
    requestp = memPoolAlloc(aio_request_pool);
    return -1;
}

static void
aio_do_opendir(aio_request_t * requestp)
{
    /* NOT IMPLEMENTED */
}

#endif

static void
aio_poll_queues(void)
{
    /* kick "overflow" request queue */
    if (request_queue2.head &&
	pthread_mutex_trylock(&request_queue.mutex) == 0) {
	*request_queue.tailp = request_queue2.head;
	request_queue.tailp = request_queue2.tailp;
	pthread_cond_signal(&request_queue.cond);
	pthread_mutex_unlock(&request_queue.mutex);
	request_queue2.head = NULL;
	request_queue2.tailp = &request_queue2.head;
    }
    /* poll done queue */
    if (done_queue.head && pthread_mutex_trylock(&done_queue.mutex) == 0) {
	struct aio_request_t *requests = done_queue.head;
	done_queue.head = NULL;
	done_queue.tailp = &done_queue.head;
	pthread_mutex_unlock(&done_queue.mutex);
	*done_requests.tailp = requests;
	request_queue_len -= 1;
	while (requests->next) {
	    requests = requests->next;
	    request_queue_len -= 1;
	}
	done_requests.tailp = &requests->next;
    }
    /* Give up the CPU to allow the threads to do their work */
    /*
     * For Andres thoughts about yield(), see
     * http://www.squid-cache.org/mail-archive/squid-dev/200012/0001.html
     */
    if (done_queue.head || request_queue.head)
#ifndef _SQUID_SOLARIS_
	sched_yield();
#else
	yield();
#endif
}

aio_result_t *
aio_poll_done(void)
{
    aio_request_t *request;
    aio_result_t *resultp;
    int cancelled;
    int polled = 0;

  AIO_REPOLL:
    request = done_requests.head;
    if (request == NULL && !polled) {
	aio_poll_queues();
	polled = 1;
	request = done_requests.head;
    }
    if (!request) {
	return NULL;
    }
    debug(41, 9) ("aio_poll_done: %p type=%d result=%p\n",
	request, request->request_type, request->resultp);
    done_requests.head = request->next;
    if (!done_requests.head)
	done_requests.tailp = &done_requests.head;
    resultp = request->resultp;
    cancelled = request->cancelled;
    aio_debug(request);
    debug(43, 5) ("DONE: %d -> %d\n", request->ret, request->err);
    aio_cleanup_request(request);
    if (cancelled)
	goto AIO_REPOLL;
    return resultp;
}				/* aio_poll_done */

int
aio_operations_pending(void)
{
    return request_queue_len + (done_requests.head ? 1 : 0);
}

int
aio_sync(void)
{
    /* XXX This might take a while if the queue is large.. */
    do {
	aio_poll_queues();
    } while (request_queue_len > 0);
    return aio_operations_pending();
}

int
aio_get_queue_len(void)
{
    return request_queue_len;
}

static void
aio_debug(aio_request_t * request)
{
    switch (request->request_type) {
    case _AIO_OP_OPEN:
	debug(43, 5) ("OPEN of %s to FD %d\n", request->path, request->ret);
	break;
    case _AIO_OP_READ:
	debug(43, 5) ("READ on fd: %d\n", request->fd);
	break;
    case _AIO_OP_WRITE:
	debug(43, 5) ("WRITE on fd: %d\n", request->fd);
	break;
    case _AIO_OP_CLOSE:
	debug(43, 5) ("CLOSE of fd: %d\n", request->fd);
	break;
    case _AIO_OP_UNLINK:
	debug(43, 5) ("UNLINK of %s\n", request->path);
	break;
    case _AIO_OP_TRUNCATE:
	debug(43, 5) ("UNLINK of %s\n", request->path);
	break;
    default:
	break;
    }
}
