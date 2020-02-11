/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 43    AIOPS */

#ifndef _REENTRANT
#error "_REENTRANT MUST be defined to build squid async io support."
#endif

#include "squid.h"
#include "DiskIO/DiskThreads/CommIO.h"
#include "DiskThreads.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"

/*
 * struct stat and squidaio_xstrdup use explicit pool alloc()/freeOne().
 * XXX: convert to MEMPROXY_CLASS() API
 */
#include "mem/Pool.h"

#include <cerrno>
#include <csignal>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <dirent.h>
#if HAVE_SCHED_H
#include <sched.h>
#endif

#define RIDICULOUS_LENGTH   4096

enum _squidaio_thread_status {
    _THREAD_STARTING = 0,
    _THREAD_WAITING,
    _THREAD_BUSY,
    _THREAD_FAILED,
    _THREAD_DONE
};
typedef enum _squidaio_thread_status squidaio_thread_status;

typedef struct squidaio_request_t {

    struct squidaio_request_t *next;
    squidaio_request_type request_type;
    int cancelled;
    char *path;
    int oflag;
    mode_t mode;
    int fd;
    char *bufferp;
    size_t buflen;
    off_t offset;
    int whence;
    int ret;
    int err;

    struct stat *tmpstatp;

    struct stat *statp;
    squidaio_result_t *resultp;
} squidaio_request_t;

typedef struct squidaio_request_queue_t {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    squidaio_request_t *volatile head;
    squidaio_request_t *volatile *volatile tailp;
    unsigned long requests;
    unsigned long blocked;  /* main failed to lock the queue */
} squidaio_request_queue_t;

typedef struct squidaio_thread_t squidaio_thread_t;

struct squidaio_thread_t {
    squidaio_thread_t *next;
    pthread_t thread;
    squidaio_thread_status status;

    struct squidaio_request_t *current_req;
    unsigned long requests;
};

static void squidaio_queue_request(squidaio_request_t *);
static void squidaio_cleanup_request(squidaio_request_t *);
void *squidaio_thread_loop(void *);
static void squidaio_do_open(squidaio_request_t *);
static void squidaio_do_read(squidaio_request_t *);
static void squidaio_do_write(squidaio_request_t *);
static void squidaio_do_close(squidaio_request_t *);
static void squidaio_do_stat(squidaio_request_t *);
static void squidaio_do_unlink(squidaio_request_t *);
#if AIO_OPENDIR
static void *squidaio_do_opendir(squidaio_request_t *);
#endif
static void squidaio_debug(squidaio_request_t *);
static void squidaio_poll_queues(void);

static squidaio_thread_t *threads = NULL;
static int squidaio_initialised = 0;

#define AIO_LARGE_BUFS  16384
#define AIO_MEDIUM_BUFS AIO_LARGE_BUFS >> 1
#define AIO_SMALL_BUFS  AIO_LARGE_BUFS >> 2
#define AIO_TINY_BUFS   AIO_LARGE_BUFS >> 3
#define AIO_MICRO_BUFS  128

static MemAllocator *squidaio_large_bufs = NULL;    /* 16K */
static MemAllocator *squidaio_medium_bufs = NULL;   /* 8K */
static MemAllocator *squidaio_small_bufs = NULL;    /* 4K */
static MemAllocator *squidaio_tiny_bufs = NULL; /* 2K */
static MemAllocator *squidaio_micro_bufs = NULL;    /* 128K */

static int request_queue_len = 0;
static MemAllocator *squidaio_request_pool = NULL;
static MemAllocator *squidaio_thread_pool = NULL;
static squidaio_request_queue_t request_queue;

static struct {
    squidaio_request_t *head, **tailp;
}

request_queue2 = {

    NULL, &request_queue2.head
};
static squidaio_request_queue_t done_queue;

static struct {
    squidaio_request_t *head, **tailp;
}

done_requests = {

    NULL, &done_requests.head
};
static pthread_attr_t globattr;
#if HAVE_SCHED_H

static struct sched_param globsched;
#endif
static pthread_t main_thread;

static MemAllocator *
squidaio_get_pool(int size)
{
    if (size <= AIO_LARGE_BUFS) {
        if (size <= AIO_MICRO_BUFS)
            return squidaio_micro_bufs;
        else if (size <= AIO_TINY_BUFS)
            return squidaio_tiny_bufs;
        else if (size <= AIO_SMALL_BUFS)
            return squidaio_small_bufs;
        else if (size <= AIO_MEDIUM_BUFS)
            return squidaio_medium_bufs;
        else
            return squidaio_large_bufs;
    }

    return NULL;
}

void *
squidaio_xmalloc(int size)
{
    void *p;
    MemAllocator *pool;

    if ((pool = squidaio_get_pool(size)) != NULL) {
        p = pool->alloc();
    } else
        p = xmalloc(size);

    return p;
}

static char *
squidaio_xstrdup(const char *str)
{
    char *p;
    int len = strlen(str) + 1;

    p = (char *)squidaio_xmalloc(len);
    strncpy(p, str, len);

    return p;
}

void
squidaio_xfree(void *p, int size)
{
    MemAllocator *pool;

    if ((pool = squidaio_get_pool(size)) != NULL) {
        pool->freeOne(p);
    } else
        xfree(p);
}

static void
squidaio_xstrfree(char *str)
{
    MemAllocator *pool;
    int len = strlen(str) + 1;

    if ((pool = squidaio_get_pool(len)) != NULL) {
        pool->freeOne(str);
    } else
        xfree(str);
}

void
squidaio_init(void)
{
    int i;
    squidaio_thread_t *threadp;

    if (squidaio_initialised)
        return;

    pthread_attr_init(&globattr);

#if HAVE_PTHREAD_ATTR_SETSCOPE

    pthread_attr_setscope(&globattr, PTHREAD_SCOPE_SYSTEM);

#endif
#if HAVE_SCHED_H

    globsched.sched_priority = 1;

#endif

    main_thread = pthread_self();

#if HAVE_SCHED_H && HAVE_PTHREAD_SETSCHEDPARAM

    pthread_setschedparam(main_thread, SCHED_OTHER, &globsched);

#endif
#if HAVE_SCHED_H

    globsched.sched_priority = 2;

#endif
#if HAVE_SCHED_H && HAVE_PTHREAD_ATTR_SETSCHEDPARAM

    pthread_attr_setschedparam(&globattr, &globsched);

#endif

    /* Give each thread a smaller 256KB stack, should be more than sufficient */
    pthread_attr_setstacksize(&globattr, 256 * 1024);

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

    // Initialize the thread I/O pipes before creating any threads
    // see bug 3189 comment 5 about race conditions.
    CommIO::Initialize();

    /* Create threads and get them to sit in their wait loop */
    squidaio_thread_pool = memPoolCreate("aio_thread", sizeof(squidaio_thread_t));

    assert(NUMTHREADS != 0);

    for (i = 0; i < NUMTHREADS; ++i) {
        threadp = (squidaio_thread_t *)squidaio_thread_pool->alloc();
        threadp->status = _THREAD_STARTING;
        threadp->current_req = NULL;
        threadp->requests = 0;
        threadp->next = threads;
        threads = threadp;

        if (pthread_create(&threadp->thread, &globattr, squidaio_thread_loop, threadp)) {
            fprintf(stderr, "Thread creation failed\n");
            threadp->status = _THREAD_FAILED;
            continue;
        }
    }

    /* Create request pool */
    squidaio_request_pool = memPoolCreate("aio_request", sizeof(squidaio_request_t));

    squidaio_large_bufs = memPoolCreate("squidaio_large_bufs", AIO_LARGE_BUFS);

    squidaio_medium_bufs = memPoolCreate("squidaio_medium_bufs", AIO_MEDIUM_BUFS);

    squidaio_small_bufs = memPoolCreate("squidaio_small_bufs", AIO_SMALL_BUFS);

    squidaio_tiny_bufs = memPoolCreate("squidaio_tiny_bufs", AIO_TINY_BUFS);

    squidaio_micro_bufs = memPoolCreate("squidaio_micro_bufs", AIO_MICRO_BUFS);

    squidaio_initialised = 1;
}

void
squidaio_shutdown(void)
{
    if (!squidaio_initialised)
        return;

    /* This is the same as in squidaio_sync */
    do {
        squidaio_poll_queues();
    } while (request_queue_len > 0);

    CommIO::NotifyIOClose();

    squidaio_initialised = 0;
}

void *
squidaio_thread_loop(void *ptr)
{
    squidaio_thread_t *threadp = (squidaio_thread_t *)ptr;
    squidaio_request_t *request;
    sigset_t newSig;

    /*
     * Make sure to ignore signals which may possibly get sent to
     * the parent squid thread.  Causes havoc with mutex's and
     * condition waits otherwise
     */

    sigemptyset(&newSig);
    sigaddset(&newSig, SIGPIPE);
    sigaddset(&newSig, SIGCHLD);
#if defined(_SQUID_LINUX_THREADS_)

    sigaddset(&newSig, SIGQUIT);
    sigaddset(&newSig, SIGTRAP);
#else

    sigaddset(&newSig, SIGUSR1);
    sigaddset(&newSig, SIGUSR2);
#endif

    sigaddset(&newSig, SIGHUP);
    sigaddset(&newSig, SIGTERM);
    sigaddset(&newSig, SIGINT);
    sigaddset(&newSig, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &newSig, NULL);

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
                squidaio_do_open(request);
                break;

            case _AIO_OP_READ:
                squidaio_do_read(request);
                break;

            case _AIO_OP_WRITE:
                squidaio_do_write(request);
                break;

            case _AIO_OP_CLOSE:
                squidaio_do_close(request);
                break;

            case _AIO_OP_UNLINK:
                squidaio_do_unlink(request);
                break;

#if AIO_OPENDIR         /* Opendir not implemented yet */

            case _AIO_OP_OPENDIR:
                squidaio_do_opendir(request);
                break;
#endif

            case _AIO_OP_STAT:
                squidaio_do_stat(request);
                break;

            default:
                request->ret = -1;
                request->err = EINVAL;
                break;
            }
        } else {        /* cancelled */
            request->ret = -1;
            request->err = EINTR;
        }

        threadp->status = _THREAD_DONE;
        /* put the request in the done queue */
        pthread_mutex_lock(&done_queue.mutex);
        *done_queue.tailp = request;
        done_queue.tailp = &request->next;
        pthread_mutex_unlock(&done_queue.mutex);
        CommIO::NotifyIOCompleted();
        ++ threadp->requests;
    }               /* while forever */

    return NULL;
}               /* squidaio_thread_loop */

static void
squidaio_queue_request(squidaio_request_t * request)
{
    static int high_start = 0;
    debugs(43, 9, "squidaio_queue_request: " << request << " type=" << request->request_type << " result=" << request->resultp);
    /* Mark it as not executed (failing result, no error) */
    request->ret = -1;
    request->err = 0;
    /* Internal housekeeping */
    request_queue_len += 1;
    request->resultp->_data = request;
    /* Play some tricks with the request_queue2 queue */
    request->next = NULL;

    if (pthread_mutex_trylock(&request_queue.mutex) == 0) {
        if (request_queue2.head) {
            /* Grab blocked requests */
            *request_queue.tailp = request_queue2.head;
            request_queue.tailp = request_queue2.tailp;
        }

        /* Enqueue request */
        *request_queue.tailp = request;

        request_queue.tailp = &request->next;

        pthread_cond_signal(&request_queue.cond);

        pthread_mutex_unlock(&request_queue.mutex);

        if (request_queue2.head) {
            /* Clear queue of blocked requests */
            request_queue2.head = NULL;
            request_queue2.tailp = &request_queue2.head;
        }
    } else {
        /* Oops, the request queue is blocked, use request_queue2 */
        *request_queue2.tailp = request;
        request_queue2.tailp = &request->next;
    }

    if (request_queue2.head) {
        static uint64_t filter = 0;
        static uint64_t filter_limit = 8192;

        if (++filter >= filter_limit) {
            filter_limit += filter;
            filter = 0;
            debugs(43, DBG_IMPORTANT, "squidaio_queue_request: WARNING - Queue congestion (growing to " << filter_limit << ")");
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
            debugs(43, DBG_IMPORTANT, "squidaio_queue_request: WARNING - Disk I/O overloading");

            if (squid_curtime >= (high_start + 15))
                debugs(43, DBG_IMPORTANT, "squidaio_queue_request: Queue Length: current=" <<
                       request_queue_len << ", high=" << queue_high <<
                       ", low=" << queue_low << ", duration=" <<
                       (long int) (squid_curtime - high_start));

            last_warn = squid_curtime;
        }
    } else {
        high_start = 0;
    }

    /* Warn if seriously overloaded */
    if (request_queue_len > RIDICULOUS_LENGTH) {
        debugs(43, DBG_CRITICAL, "squidaio_queue_request: Async request queue growing uncontrollably!");
        debugs(43, DBG_CRITICAL, "squidaio_queue_request: Syncing pending I/O operations.. (blocking)");
        squidaio_sync();
        debugs(43, DBG_CRITICAL, "squidaio_queue_request: Synced");
    }
}               /* squidaio_queue_request */

static void
squidaio_cleanup_request(squidaio_request_t * requestp)
{
    squidaio_result_t *resultp = requestp->resultp;
    int cancelled = requestp->cancelled;

    /* Free allocated structures and copy data back to user space if the */
    /* request hasn't been cancelled */

    switch (requestp->request_type) {

    case _AIO_OP_STAT:

        if (!cancelled && requestp->ret == 0)
            memcpy(requestp->statp, requestp->tmpstatp, sizeof(struct stat));

        squidaio_xfree(requestp->tmpstatp, sizeof(struct stat));

        squidaio_xstrfree(requestp->path);

        break;

    case _AIO_OP_OPEN:
        if (cancelled && requestp->ret >= 0)
            /* The open() was cancelled but completed */
            close(requestp->ret);

        squidaio_xstrfree(requestp->path);

        break;

    case _AIO_OP_CLOSE:
        if (cancelled && requestp->ret < 0)
            /* The close() was cancelled and never got executed */
            close(requestp->fd);

        break;

    case _AIO_OP_UNLINK:

    case _AIO_OP_OPENDIR:
        squidaio_xstrfree(requestp->path);

        break;

    case _AIO_OP_READ:
        break;

    case _AIO_OP_WRITE:
        break;

    default:
        break;
    }

    if (resultp != NULL && !cancelled) {
        resultp->aio_return = requestp->ret;
        resultp->aio_errno = requestp->err;
    }

    squidaio_request_pool->freeOne(requestp);
}               /* squidaio_cleanup_request */

int
squidaio_cancel(squidaio_result_t * resultp)
{
    squidaio_request_t *request = (squidaio_request_t *)resultp->_data;

    if (request && request->resultp == resultp) {
        debugs(43, 9, "squidaio_cancel: " << request << " type=" << request->request_type << " result=" << request->resultp);
        request->cancelled = 1;
        request->resultp = NULL;
        resultp->_data = NULL;
        resultp->result_type = _AIO_OP_NONE;
        return 0;
    }

    return 1;
}               /* squidaio_cancel */

int
squidaio_open(const char *path, int oflag, mode_t mode, squidaio_result_t * resultp)
{
    squidaio_init();
    squidaio_request_t *requestp;

    requestp = (squidaio_request_t *)squidaio_request_pool->alloc();

    requestp->path = (char *) squidaio_xstrdup(path);

    requestp->oflag = oflag;

    requestp->mode = mode;

    requestp->resultp = resultp;

    requestp->request_type = _AIO_OP_OPEN;

    requestp->cancelled = 0;

    resultp->result_type = _AIO_OP_OPEN;

    squidaio_queue_request(requestp);

    return 0;
}

static void
squidaio_do_open(squidaio_request_t * requestp)
{
    requestp->ret = open(requestp->path, requestp->oflag, requestp->mode);
    requestp->err = errno;
}

int
squidaio_read(int fd, char *bufp, size_t bufs, off_t offset, int whence, squidaio_result_t * resultp)
{
    squidaio_request_t *requestp;

    requestp = (squidaio_request_t *)squidaio_request_pool->alloc();

    requestp->fd = fd;

    requestp->bufferp = bufp;

    requestp->buflen = bufs;

    requestp->offset = offset;

    requestp->whence = whence;

    requestp->resultp = resultp;

    requestp->request_type = _AIO_OP_READ;

    requestp->cancelled = 0;

    resultp->result_type = _AIO_OP_READ;

    squidaio_queue_request(requestp);

    return 0;
}

static void
squidaio_do_read(squidaio_request_t * requestp)
{
    if (lseek(requestp->fd, requestp->offset, requestp->whence) >= 0)
        requestp->ret = read(requestp->fd, requestp->bufferp, requestp->buflen);
    else
        requestp->ret = -1;
    requestp->err = errno;
}

int
squidaio_write(int fd, char *bufp, size_t bufs, off_t offset, int whence, squidaio_result_t * resultp)
{
    squidaio_request_t *requestp;

    requestp = (squidaio_request_t *)squidaio_request_pool->alloc();

    requestp->fd = fd;

    requestp->bufferp = bufp;

    requestp->buflen = bufs;

    requestp->offset = offset;

    requestp->whence = whence;

    requestp->resultp = resultp;

    requestp->request_type = _AIO_OP_WRITE;

    requestp->cancelled = 0;

    resultp->result_type = _AIO_OP_WRITE;

    squidaio_queue_request(requestp);

    return 0;
}

static void
squidaio_do_write(squidaio_request_t * requestp)
{
    requestp->ret = write(requestp->fd, requestp->bufferp, requestp->buflen);
    requestp->err = errno;
}

int
squidaio_close(int fd, squidaio_result_t * resultp)
{
    squidaio_request_t *requestp;

    requestp = (squidaio_request_t *)squidaio_request_pool->alloc();

    requestp->fd = fd;

    requestp->resultp = resultp;

    requestp->request_type = _AIO_OP_CLOSE;

    requestp->cancelled = 0;

    resultp->result_type = _AIO_OP_CLOSE;

    squidaio_queue_request(requestp);

    return 0;
}

static void
squidaio_do_close(squidaio_request_t * requestp)
{
    requestp->ret = close(requestp->fd);
    requestp->err = errno;
}

int

squidaio_stat(const char *path, struct stat *sb, squidaio_result_t * resultp)
{
    squidaio_init();
    squidaio_request_t *requestp;

    requestp = (squidaio_request_t *)squidaio_request_pool->alloc();

    requestp->path = (char *) squidaio_xstrdup(path);

    requestp->statp = sb;

    requestp->tmpstatp = (struct stat *) squidaio_xmalloc(sizeof(struct stat));

    requestp->resultp = resultp;

    requestp->request_type = _AIO_OP_STAT;

    requestp->cancelled = 0;

    resultp->result_type = _AIO_OP_STAT;

    squidaio_queue_request(requestp);

    return 0;
}

static void
squidaio_do_stat(squidaio_request_t * requestp)
{
    requestp->ret = stat(requestp->path, requestp->tmpstatp);
    requestp->err = errno;
}

int
squidaio_unlink(const char *path, squidaio_result_t * resultp)
{
    squidaio_init();
    squidaio_request_t *requestp;

    requestp = (squidaio_request_t *)squidaio_request_pool->alloc();

    requestp->path = squidaio_xstrdup(path);

    requestp->resultp = resultp;

    requestp->request_type = _AIO_OP_UNLINK;

    requestp->cancelled = 0;

    resultp->result_type = _AIO_OP_UNLINK;

    squidaio_queue_request(requestp);

    return 0;
}

static void
squidaio_do_unlink(squidaio_request_t * requestp)
{
    requestp->ret = unlink(requestp->path);
    requestp->err = errno;
}

#if AIO_OPENDIR
/* XXX squidaio_opendir NOT implemented yet.. */

int
squidaio_opendir(const char *path, squidaio_result_t * resultp)
{
    squidaio_request_t *requestp;
    int len;

    requestp = squidaio_request_pool->alloc();

    resultp->result_type = _AIO_OP_OPENDIR;

    return -1;
}

static void
squidaio_do_opendir(squidaio_request_t * requestp)
{
    /* NOT IMPLEMENTED */
}

#endif

static void
squidaio_poll_queues(void)
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

        struct squidaio_request_t *requests = done_queue.head;
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
}

squidaio_result_t *
squidaio_poll_done(void)
{
    squidaio_request_t *request;
    squidaio_result_t *resultp;
    int cancelled;
    int polled = 0;

AIO_REPOLL:
    request = done_requests.head;

    if (request == NULL && !polled) {
        CommIO::ResetNotifications();
        squidaio_poll_queues();
        polled = 1;
        request = done_requests.head;
    }

    if (!request) {
        return NULL;
    }

    debugs(43, 9, "squidaio_poll_done: " << request << " type=" << request->request_type << " result=" << request->resultp);
    done_requests.head = request->next;

    if (!done_requests.head)
        done_requests.tailp = &done_requests.head;

    resultp = request->resultp;

    cancelled = request->cancelled;

    squidaio_debug(request);

    debugs(43, 5, "DONE: " << request->ret << " -> " << request->err);

    squidaio_cleanup_request(request);

    if (cancelled)
        goto AIO_REPOLL;

    return resultp;
}               /* squidaio_poll_done */

int
squidaio_operations_pending(void)
{
    return request_queue_len + (done_requests.head ? 1 : 0);
}

int
squidaio_sync(void)
{
    /* XXX This might take a while if the queue is large.. */

    do {
        squidaio_poll_queues();
    } while (request_queue_len > 0);

    return squidaio_operations_pending();
}

int
squidaio_get_queue_len(void)
{
    return request_queue_len;
}

static void
squidaio_debug(squidaio_request_t * request)
{
    switch (request->request_type) {

    case _AIO_OP_OPEN:
        debugs(43, 5, "OPEN of " << request->path << " to FD " << request->ret);
        break;

    case _AIO_OP_READ:
        debugs(43, 5, "READ on fd: " << request->fd);
        break;

    case _AIO_OP_WRITE:
        debugs(43, 5, "WRITE on fd: " << request->fd);
        break;

    case _AIO_OP_CLOSE:
        debugs(43, 5, "CLOSE of fd: " << request->fd);
        break;

    case _AIO_OP_UNLINK:
        debugs(43, 5, "UNLINK of " << request->path);
        break;

    default:
        break;
    }
}

void
squidaio_stats(StoreEntry * sentry)
{
    squidaio_thread_t *threadp;
    int i;

    if (!squidaio_initialised)
        return;

    storeAppendPrintf(sentry, "\n\nThreads Status:\n");

    storeAppendPrintf(sentry, "#\tID\t# Requests\n");

    threadp = threads;

    for (i = 0; i < NUMTHREADS; ++i) {
        storeAppendPrintf(sentry, "%i\t0x%lx\t%ld\n", i + 1, (unsigned long)threadp->thread, threadp->requests);
        threadp = threadp->next;
    }
}

