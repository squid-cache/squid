/*
 * $Id: aiops.cc,v 1.1 2000/05/03 17:15:46 adrian Exp $
 *
 * DEBUG: section 43    AIOPS
 * AUTHOR: Stewart Forster <slf@connect.com.au>
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

#if defined(_SQUID_LINUX_)
/* Linux requires proper use of mutexes or it will segfault deep in the
 * thread libraries. Observed on Alpha SMP Linux 2.2.10-ac12.
 */
#define AIO_PROPER_MUTEX 1
#endif

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
    _AIO_OP_OPENDIR,
    _AIO_OP_STAT
};

typedef struct aio_request_t {
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
    struct aio_request_t *next;
} aio_request_t;


typedef struct aio_thread_t {
    pthread_t thread;
    enum _aio_thread_status status;
    pthread_mutex_t mutex;	/* Mutex for testing condition variable */
    pthread_cond_t cond;	/* Condition variable */
    struct aio_request_t *volatile req;		/* set by main, cleared by thread */
    struct aio_request_t *processed_req;	/* reminder to main */
    struct aio_thread_t *next;
} aio_thread_t;


int aio_cancel(aio_result_t *);
int aio_open(const char *, int, mode_t, aio_result_t *);
int aio_read(int, char *, int, off_t, int, aio_result_t *);
int aio_write(int, char *, int, off_t, int, aio_result_t *);
int aio_close(int, aio_result_t *);
int aio_unlink(const char *, aio_result_t *);
int aio_opendir(const char *, aio_result_t *);
aio_result_t *aio_poll_done();
int aio_sync(void);

static void aio_init(void);
static void aio_queue_request(aio_request_t *);
static void aio_process_request_queue(void);
static void aio_cleanup_request(aio_request_t *);
static void *aio_thread_loop(void *);
static void aio_do_open(aio_request_t *);
static void aio_do_read(aio_request_t *);
static void aio_do_write(aio_request_t *);
static void aio_do_close(aio_request_t *);
static void aio_do_stat(aio_request_t *);
static void aio_do_unlink(aio_request_t *);
#if AIO_OPENDIR
static void *aio_do_opendir(aio_request_t *);
#endif
static void aio_debug(aio_request_t *);
static void aio_poll_threads(void);

static aio_thread_t *threads;
static int aio_initialised = 0;

static int request_queue_len = 0;
static MemPool *aio_request_pool = NULL;
static aio_request_t *request_queue_head = NULL;
static aio_request_t *request_queue_tail = NULL;
static aio_request_t *request_done_head = NULL;
static aio_request_t *request_done_tail = NULL;
static aio_thread_t *wait_threads = NULL;
static aio_thread_t *busy_threads_head = NULL;
static aio_thread_t *busy_threads_tail = NULL;
static pthread_attr_t globattr;
static struct sched_param globsched;
static pthread_t main_thread;

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

    /* Create threads and get them to sit in their wait loop */
    threads = xcalloc(NUMTHREADS, sizeof(aio_thread_t));

    for (i = 0; i < NUMTHREADS; i++) {
	threadp = &threads[i];
	threadp->status = _THREAD_STARTING;
	if (pthread_mutex_init(&(threadp->mutex), NULL)) {
	    threadp->status = _THREAD_FAILED;
	    continue;
	}
	if (pthread_cond_init(&(threadp->cond), NULL)) {
	    threadp->status = _THREAD_FAILED;
	    continue;
	}
	threadp->req = NULL;
	threadp->processed_req = NULL;
	if (pthread_create(&threadp->thread, &globattr, aio_thread_loop, threadp)) {
	    fprintf(stderr, "Thread creation failed\n");
	    threadp->status = _THREAD_FAILED;
	    continue;
	}
	threadp->next = wait_threads;
	wait_threads = threadp;
#if AIO_PROPER_MUTEX
	pthread_mutex_lock(&threadp->mutex);
#endif
    }

    /* Create request pool */
    aio_request_pool = memPoolCreate("aio_request", sizeof(aio_request_t));

    aio_initialised = 1;
}


static void *
aio_thread_loop(void *ptr)
{
    aio_thread_t *threadp = ptr;
    aio_request_t *request;
    sigset_t new;
#if !AIO_PROPER_MUTEX
    struct timespec wait_time;
#endif

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

    pthread_mutex_lock(&threadp->mutex);
    while (1) {
#if AIO_PROPER_MUTEX
	while (threadp->req == NULL) {
	    threadp->status = _THREAD_WAITING;
	    pthread_cond_wait(&threadp->cond, &threadp->mutex);
	}
#else
	/* The timeout is used to unlock the race condition where
	 * ->req is set between the check and pthread_cond_wait.
	 * The thread steps it's own clock on each timeout, to avoid a CPU
	 * spin situation if the main thread is suspended (paging), and
	 * squid_curtime is not being updated timely.
	 */
	wait_time.tv_sec = squid_curtime + 1;	/* little quicker first time */
	wait_time.tv_nsec = 0;
	while (threadp->req == NULL) {
	    threadp->status = _THREAD_WAITING;
	    pthread_cond_timedwait(&threadp->cond, &threadp->mutex, &wait_time);
	    wait_time.tv_sec += 3;	/* then wait 3 seconds between each check */
	}
#endif
	request = threadp->req;
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
	threadp->req = NULL;	/* tells main thread that we are done */
    }				/* while */
    return NULL;
}				/* aio_thread_loop */

static void
aio_do_request(aio_request_t * requestp)
{
    if (wait_threads == NULL && busy_threads_head == NULL) {
	fprintf(stderr, "PANIC: No threads to service requests with!\n");
	exit(-1);
    }
    aio_queue_request(requestp);
}				/* aio_do_request */


static void
aio_queue_request(aio_request_t * requestp)
{
    aio_request_t *rp;
    static int last_warn = 0;
    static int high_start = 0;
    static int queue_high, queue_low;
    int i;

    /* Mark it as not executed (failing result, no error) */
    requestp->ret = -1;
    requestp->err = 0;
    /* Queue it on the request queue */
    if (request_queue_head == NULL) {
	request_queue_head = requestp;
	request_queue_tail = requestp;
    } else {
	request_queue_tail->next = requestp;
	request_queue_tail = requestp;
    }
    requestp->next = NULL;
    request_queue_len += 1;
    /* Poll done threads if needed */
    if (wait_threads == NULL)
	aio_poll_threads();
    /* Kick it rolling */
    aio_process_request_queue();
    /* Warn if out of threads */
    if (request_queue_len > (NUMTHREADS >> 1)) {
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
	    squid_curtime >= (high_start + 3)) {
	    debug(43, 1) ("aio_queue_request: WARNING - Running out of I/O threads\n");
	    debug(43, 2) ("aio_queue_request: Queue Length: current=%d, high=%d, low=%d, duration=%d\n",
		request_queue_len, queue_high, queue_low, squid_curtime - high_start);
	    debug(43, 1) ("aio_queue_request: Perhaps you should increase NUMTHREADS\n");
	    debug(43, 1) ("aio_queue_request: Or install more disks to share the load\n");
	    debug(43, 3) ("aio_queue_request: First %d items on request queue\n", NUMTHREADS);
	    rp = request_queue_head;
	    for (i = 1; i <= NUMTHREADS; i++) {
		switch (rp->request_type) {
		case _AIO_OP_OPEN:
		    debug(43, 3) ("aio_queue_request: %d : open -> %s\n", i, rp->path);
		    break;
		case _AIO_OP_READ:
		    debug(43, 3) ("aio_queue_request: %d : read -> FD = %d\n", i, rp->fd);
		    break;
		case _AIO_OP_WRITE:
		    debug(43, 3) ("aio_queue_request: %d : write -> FD = %d\n", i, rp->fd);
		    break;
		case _AIO_OP_CLOSE:
		    debug(43, 3) ("aio_queue_request: %d : close -> FD = %d\n", i, rp->fd);
		    break;
		case _AIO_OP_UNLINK:
		    debug(43, 3) ("aio_queue_request: %d : unlink -> %s\n", i, rp->path);
		    break;
		case _AIO_OP_STAT:
		    debug(43, 3) ("aio_queue_request: %d : stat -> %s\n", i, rp->path);
		    break;
		default:
		    debug(43, 1) ("aio_queue_request: %d : Unimplemented request type: %d\n", i, rp->request_type);
		    break;
		}
		if ((rp = rp->next) == NULL)
		    break;
	    }
	    last_warn = squid_curtime;
	}
    } else {
	high_start = 0;
    }
    if (request_queue_len > RIDICULOUS_LENGTH) {
	debug(43, 0) ("aio_queue_request: Async request queue growing uncontrollably!\n");
	debug(43, 0) ("aio_queue_request: Syncing pending I/O operations.. (blocking)\n");
	aio_sync();
	debug(43, 0) ("aio_queue_request: Synced\n");
    }
}				/* aio_queue_request */


static void
aio_process_request_queue(void)
{
    aio_thread_t *threadp;
    aio_request_t *requestp;

    for (;;) {
	if (wait_threads == NULL || request_queue_head == NULL)
	    return;

	requestp = request_queue_head;
	if ((request_queue_head = requestp->next) == NULL)
	    request_queue_tail = NULL;
	requestp->next = NULL;
	request_queue_len--;

	if (requestp->cancelled) {
	    aio_cleanup_request(requestp);
	    continue;
	}
	threadp = wait_threads;
	wait_threads = threadp->next;
	threadp->next = NULL;

	if (busy_threads_head != NULL)
	    busy_threads_tail->next = threadp;
	else
	    busy_threads_head = threadp;
	busy_threads_tail = threadp;

	threadp->status = _THREAD_BUSY;
	threadp->req = threadp->processed_req = requestp;
	pthread_cond_signal(&(threadp->cond));
#if AIO_PROPER_MUTEX
	pthread_mutex_unlock(&threadp->mutex);
#endif
    }
}				/* aio_process_request_queue */


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
	xfree(requestp->tmpstatp);
    case _AIO_OP_OPEN:
	if (cancelled && requestp->ret >= 0)
	    /* The open() was cancelled but completed */
	    close(requestp->ret);
	xfree(requestp->path);
	break;
    case _AIO_OP_CLOSE:
	if (cancelled && requestp->ret < 0)
	    /* The close() was cancelled and never got executed */
	    close(requestp->fd);
	break;
    case _AIO_OP_UNLINK:
    case _AIO_OP_OPENDIR:
	xfree(requestp->path);
	break;
    case _AIO_OP_READ:
	if (!cancelled && requestp->ret > 0)
	    xmemcpy(requestp->bufferp, requestp->tmpbufp, requestp->ret);
    case _AIO_OP_WRITE:
	xfree(requestp->tmpbufp);
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
    aio_thread_t *threadp;
    aio_request_t *requestp;

    for (threadp = busy_threads_head; threadp != NULL; threadp = threadp->next)
	if (threadp->processed_req->resultp == resultp) {
	    threadp->processed_req->cancelled = 1;
	    threadp->processed_req->resultp = NULL;
	    return 0;
	}
    for (requestp = request_queue_head; requestp != NULL; requestp = requestp->next)
	if (requestp->resultp == resultp) {
	    requestp->cancelled = 1;
	    requestp->resultp = NULL;
	    return 0;
	}
    for (requestp = request_done_head; requestp != NULL; requestp = requestp->next)
	if (requestp->resultp == resultp) {
	    requestp->cancelled = 1;
	    requestp->resultp = NULL;
	    return 0;
	}
    return 1;
}				/* aio_cancel */


int
aio_open(const char *path, int oflag, mode_t mode, aio_result_t * resultp)
{
    aio_request_t *requestp;
    int len;

    if (!aio_initialised)
	aio_init();
    if ((requestp = memPoolAlloc(aio_request_pool)) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    len = strlen(path) + 1;
    if ((requestp->path = (char *) xmalloc(len)) == NULL) {
	memPoolFree(aio_request_pool, requestp);
	errno = ENOMEM;
	return -1;
    }
    strncpy(requestp->path, path, len);
    requestp->oflag = oflag;
    requestp->mode = mode;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_OPEN;
    requestp->cancelled = 0;

    aio_do_request(requestp);
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
    if ((requestp = memPoolAlloc(aio_request_pool)) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    requestp->fd = fd;
    requestp->bufferp = bufp;
    if ((requestp->tmpbufp = (char *) xmalloc(bufs)) == NULL) {
	memPoolFree(aio_request_pool, requestp);
	errno = ENOMEM;
	return -1;
    }
    requestp->buflen = bufs;
    requestp->offset = offset;
    requestp->whence = whence;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_READ;
    requestp->cancelled = 0;

    aio_do_request(requestp);
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
    if ((requestp = memPoolAlloc(aio_request_pool)) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    requestp->fd = fd;
    if ((requestp->tmpbufp = (char *) xmalloc(bufs)) == NULL) {
	memPoolFree(aio_request_pool, requestp);
	errno = ENOMEM;
	return -1;
    }
    xmemcpy(requestp->tmpbufp, bufp, bufs);
    requestp->buflen = bufs;
    requestp->offset = offset;
    requestp->whence = whence;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_WRITE;
    requestp->cancelled = 0;

    aio_do_request(requestp);
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
    if ((requestp = memPoolAlloc(aio_request_pool)) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    requestp->fd = fd;
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_CLOSE;
    requestp->cancelled = 0;

    aio_do_request(requestp);
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
    int len;

    if (!aio_initialised)
	aio_init();
    if ((requestp = memPoolAlloc(aio_request_pool)) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    len = strlen(path) + 1;
    if ((requestp->path = (char *) xmalloc(len)) == NULL) {
	memPoolFree(aio_request_pool, requestp);
	errno = ENOMEM;
	return -1;
    }
    strncpy(requestp->path, path, len);
    requestp->statp = sb;
    if ((requestp->tmpstatp = (struct stat *) xmalloc(sizeof(struct stat))) == NULL) {
	xfree(requestp->path);
	memPoolFree(aio_request_pool, requestp);
	errno = ENOMEM;
	return -1;
    }
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_STAT;
    requestp->cancelled = 0;

    aio_do_request(requestp);
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
    int len;

    if (!aio_initialised)
	aio_init();
    if ((requestp = memPoolAlloc(aio_request_pool)) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    len = strlen(path) + 1;
    if ((requestp->path = (char *) xmalloc(len)) == NULL) {
	memPoolFree(aio_request_pool, requestp);
	errno = ENOMEM;
	return -1;
    }
    strncpy(requestp->path, path, len);
    requestp->resultp = resultp;
    requestp->request_type = _AIO_OP_UNLINK;
    requestp->cancelled = 0;

    aio_do_request(requestp);
    return 0;
}


static void
aio_do_unlink(aio_request_t * requestp)
{
    requestp->ret = unlink(requestp->path);
    requestp->err = errno;
}


#if AIO_OPENDIR
/* XXX aio_opendir NOT implemented? */

int
aio_opendir(const char *path, aio_result_t * resultp)
{
    aio_request_t *requestp;
    int len;

    if (!aio_initialised)
	aio_init();
    if ((requestp = memPoolAlloc(aio_request_pool)) == NULL) {
	errno = ENOMEM;
	return -1;
    }
    return -1;
}

static void
aio_do_opendir(aio_request_t * requestp)
{
    /* NOT IMPLEMENTED */
}

#endif


void
aio_poll_threads(void)
{
    aio_thread_t *prev;
    aio_thread_t *threadp;
    aio_request_t *requestp;

    do {			/* while found completed thread */
	prev = NULL;
	threadp = busy_threads_head;
	while (threadp) {
	    debug(43, 9) ("aio_poll_threads: %p: request type %d -> status %d\n",
		threadp,
		threadp->processed_req->request_type,
		threadp->status);
#if AIO_PROPER_MUTEX
	    if (threadp->req == NULL)
		if (pthread_mutex_trylock(&threadp->mutex) == 0)
		    break;
#else
	    if (threadp->req == NULL)
		break;
#endif
	    prev = threadp;
	    threadp = threadp->next;
	}
	if (threadp == NULL)
	    break;

	if (prev == NULL)
	    busy_threads_head = busy_threads_head->next;
	else
	    prev->next = threadp->next;

	if (busy_threads_tail == threadp)
	    busy_threads_tail = prev;

	requestp = threadp->processed_req;
	threadp->processed_req = NULL;

	threadp->next = wait_threads;
	wait_threads = threadp;

	if (request_done_tail != NULL)
	    request_done_tail->next = requestp;
	else
	    request_done_head = requestp;
	request_done_tail = requestp;
    } while (threadp);

    aio_process_request_queue();
}				/* aio_poll_threads */

aio_result_t *
aio_poll_done(void)
{
    aio_request_t *requestp;
    aio_result_t *resultp;
    int cancelled;

  AIO_REPOLL:
    aio_poll_threads();
    if (request_done_head == NULL) {
	return NULL;
    }
    requestp = request_done_head;
    request_done_head = requestp->next;
    if (!request_done_head)
	request_done_tail = NULL;

    resultp = requestp->resultp;
    cancelled = requestp->cancelled;
    aio_debug(requestp);
    debug(43, 5) ("DONE: %d -> %d\n", requestp->ret, requestp->err);
    aio_cleanup_request(requestp);
    if (cancelled)
	goto AIO_REPOLL;
    return resultp;
}				/* aio_poll_done */

int
aio_operations_pending(void)
{
    return request_queue_len + (request_done_head != NULL) + (busy_threads_head != NULL);
}

int
aio_overloaded(void)
{
    static time_t last_warn = 0;
    if (aio_operations_pending() > RIDICULOUS_LENGTH / 4) {
	if (squid_curtime >= (last_warn + 15)) {
	    debug(43, 0) ("Warning: Async-IO overloaded\n");
	    last_warn = squid_curtime;
	}
	return 1;
    }
    return 0;
}

int
aio_sync(void)
{
    int loop_count = 0;
    do {
	aio_poll_threads();
	assert(++loop_count < 10);
    } while (request_queue_len > 0);
    return aio_operations_pending();
}

int
aio_get_queue_len(void)
{
    return request_queue_len;
}

static void
aio_debug(aio_request_t * requestp)
{
    switch (requestp->request_type) {
    case _AIO_OP_OPEN:
	debug(43, 5) ("OPEN of %s to FD %d\n", requestp->path, requestp->ret);
	break;
    case _AIO_OP_READ:
	debug(43, 5) ("READ on fd: %d\n", requestp->fd);
	break;
    case _AIO_OP_WRITE:
	debug(43, 5) ("WRITE on fd: %d\n", requestp->fd);
	break;
    case _AIO_OP_CLOSE:
	debug(43, 5) ("CLOSE of fd: %d\n", requestp->fd);
	break;
    case _AIO_OP_UNLINK:
	debug(43, 5) ("UNLINK of %s\n", requestp->path);
	break;
    default:
	break;
    }
}
