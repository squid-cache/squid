/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section --    External DISKD process implementation. */

#include "squid.h"
#include "DiskIO/DiskDaemon/diomsg.h"
#include "hash.h"

#include <cerrno>
#include <iostream>
#if HAVE_SYS_IPC_H
#include <sys/ipc.h>
#endif
#if HAVE_SYS_MSG_H
#include <sys/msg.h>
#endif
#if HAVE_SYS_SHM_H
#include <sys/shm.h>
#endif

void
xassert(const char *msg, const char *file, int line)
{
    fprintf(stderr,"assertion failed: %s:%d: \"%s\"\n", file, line, msg);

    abort();
}

const int diomsg::msg_snd_rcv_sz = sizeof(diomsg) - sizeof(mtyp_t);
#define DEBUG(LEVEL) if ((LEVEL) <= DebugLevel)

typedef struct _file_state file_state;

struct _file_state {
    void *key;
    file_state *next;
    int id;
    int fd;
    off_t offset;
};

static hash_table *hash = NULL;
static pid_t mypid;
static char *shmbuf;
static int DebugLevel = 0;

static int
do_open(diomsg * r, int, const char *buf)
{
    int fd;
    file_state *fs;
    /*
     * note r->offset holds open() flags
     */
    fd = open(buf, r->offset, 0600);

    if (fd < 0) {
        DEBUG(1) {
            fprintf(stderr, "%d %s: ", (int) mypid, buf);
            perror("open");
        }

        return -errno;
    }

    fs = (file_state *)xcalloc(1, sizeof(*fs));
    fs->id = r->id;
    fs->key = &fs->id;          /* gack */
    fs->fd = fd;
    hash_join(hash, (hash_link *) fs);
    DEBUG(2) {
        fprintf(stderr, "%d OPEN  id %d, FD %d, fs %p\n",
                (int) mypid,
                fs->id,
                fs->fd,
                fs);
    }
    return fd;
}

static int
do_close(diomsg * r, int)
{
    int fd;
    file_state *fs;
    fs = (file_state *) hash_lookup(hash, &r->id);

    if (NULL == fs) {
        errno = EBADF;
        DEBUG(1) {
            fprintf(stderr, "%d CLOSE id %d: ", (int) mypid, r->id);
            perror("do_close");
        }

        return -errno;
    }

    fd = fs->fd;
    hash_remove_link(hash, (hash_link *) fs);
    DEBUG(2) {
        fprintf(stderr, "%d CLOSE id %d, FD %d, fs %p\n",
                (int) mypid,
                r->id,
                fs->fd,
                fs);
    }
    xfree(fs);
    return close(fd);
}

static int
do_read(diomsg * r, int, char *buf)
{
    int x;
    int readlen = r->size;
    file_state *fs;
    fs = (file_state *) hash_lookup(hash, &r->id);

    if (NULL == fs) {
        errno = EBADF;
        DEBUG(1) {
            fprintf(stderr, "%d READ  id %d: ", (int) mypid, r->id);
            perror("do_read");
        }

        return -errno;
    }

    if (r->offset > -1 && r->offset != fs->offset) {
        DEBUG(2) {
            fprintf(stderr, "seeking to %" PRId64 "\n", (int64_t)r->offset);
        }

        if (lseek(fs->fd, r->offset, SEEK_SET) < 0) {
            DEBUG(1) {
                fprintf(stderr, "%d FD %d, offset %" PRId64 ": ", (int) mypid, fs->fd, (int64_t)r->offset);
                perror("lseek");
            }
        }
    }

    x = read(fs->fd, buf, readlen);
    DEBUG(2) {
        fprintf(stderr, "%d READ %d,%d,%" PRId64 " ret %d\n", (int) mypid,
                fs->fd, readlen, (int64_t)r->offset, x);
    }

    if (x < 0) {
        DEBUG(1) {
            fprintf(stderr, "%d FD %d: ", (int) mypid, fs->fd);
            perror("read");
        }

        return -errno;
    }

    fs->offset = r->offset + x;
    return x;
}

static int
do_write(diomsg * r, int, const char *buf)
{
    int wrtlen = r->size;
    int x;
    file_state *fs;
    fs = (file_state *) hash_lookup(hash, &r->id);

    if (NULL == fs) {
        errno = EBADF;
        DEBUG(1) {
            fprintf(stderr, "%d WRITE id %d: ", (int) mypid, r->id);
            perror("do_write");
        }

        return -errno;
    }

    if (r->offset > -1 && r->offset != fs->offset) {
        if (lseek(fs->fd, r->offset, SEEK_SET) < 0) {
            DEBUG(1) {
                fprintf(stderr, "%d FD %d, offset %" PRId64 ": ", (int) mypid, fs->fd, (int64_t)r->offset);
                perror("lseek");
            }
        }
    }

    DEBUG(2) {
        fprintf(stderr, "%d WRITE %d,%d,%" PRId64 "\n", (int) mypid,
                fs->fd, wrtlen, (int64_t)r->offset);
    }
    x = write(fs->fd, buf, wrtlen);

    if (x < 0) {
        DEBUG(1) {
            fprintf(stderr, "%d FD %d: ", (int) mypid, fs->fd);
            perror("write");
        }

        return -errno;
    }

    fs->offset = r->offset + x;
    return x;
}

static int
do_unlink(diomsg * r, int, const char *buf)
{
    if (unlink(buf) < 0) {
        DEBUG(1) {
            fprintf(stderr, "%d UNLNK id %d %s: ", (int) mypid, r->id, buf);
            perror("unlink");
        }

        return -errno;
    }

    DEBUG(2) {
        fprintf(stderr, "%d UNLNK %s\n", (int) mypid, buf);
    }
    return 0;
}

static void
msg_handle(diomsg * r, int rl, diomsg * s)
{
    char *buf = NULL;
    s->mtype = r->mtype;
    s->id = r->id;
    s->seq_no = r->seq_no;      /* optional, debugging */
    s->callback_data = r->callback_data;
    s->requestor = r->requestor;
    s->size = 0;                /* optional, debugging */
    s->offset = 0;              /* optional, debugging */
    s->shm_offset = r->shm_offset;
    s->newstyle = r->newstyle;

    if (s->shm_offset > -1)
        buf = shmbuf + s->shm_offset;
    else if (r->mtype != _MQD_CLOSE) {
        fprintf(stderr, "%d UNLNK id(%u) Error: no filename in shm buffer\n", (int) mypid, s->id);
        return;
    }

    switch (r->mtype) {

    case _MQD_OPEN:

    case _MQD_CREATE:
        s->status = do_open(r, rl, buf);
        break;

    case _MQD_CLOSE:
        s->status = do_close(r, rl);
        break;

    case _MQD_READ:
        s->status = do_read(r, rl, buf);
        break;

    case _MQD_WRITE:
        s->status = do_write(r, rl, buf);
        break;

    case _MQD_UNLINK:
        s->status = do_unlink(r, rl, buf);
        break;

    default:
        assert(0);
        break;
    }
}

static int
fsCmp(const void *a, const void *b)
{
    const int *A = (const int *)a;
    const int *B = (const int *)b;
    return *A != *B;
}

static unsigned int
fsHash(const void *key, unsigned int n)
{
    /* note, n must be a power of 2! */
    const int *k = (const int *)key;
    return (*k & (--n));
}

extern "C" {
    static void alarm_handler(int) {}
};

int
main(int argc, char *argv[])
{
    int key;
    int rmsgid;
    int smsgid;
    int shmid;
    diomsg rmsg;
    diomsg smsg;
    int rlen;
    char rbuf[512];

    struct sigaction sa;
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    mypid = getpid();
    assert(4 == argc);
    key = atoi(argv[1]);
    rmsgid = msgget(key, 0600);

    if (rmsgid < 0) {
        perror("msgget");
        return 1;
    }

    key = atoi(argv[2]);
    smsgid = msgget(key, 0600);

    if (smsgid < 0) {
        perror("msgget");
        return 1;
    }

    key = atoi(argv[3]);
    shmid = shmget(key, 0, 0600);

    if (shmid < 0) {
        perror("shmget");
        return 1;
    }

    shmbuf = (char *)shmat(shmid, NULL, 0);

    if (shmbuf == (void *) -1) {
        perror("shmat");
        return 1;
    }

    hash = hash_create(fsCmp, 1 << 4, fsHash);
    assert(hash);
    if (fcntl(0, F_SETFL, SQUID_NONBLOCK) < 0) {
        perror(xstrerr(errno));
        return 1;
    }
    memset(&sa, '\0', sizeof(sa));
    sa.sa_handler = alarm_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, NULL);

    for (;;) {
        alarm(1);
        memset(&rmsg, '\0', sizeof(rmsg));
        DEBUG(2) {
            std::cerr << "msgrcv: " << rmsgid << ", "
                      << &rmsg << ", " << diomsg::msg_snd_rcv_sz
                      << ", " << 0 << ", " << 0 << std::endl;
        }
        rlen = msgrcv(rmsgid, &rmsg, diomsg::msg_snd_rcv_sz, 0, 0);

        if (rlen < 0) {
            if (EINTR == errno) {
                if (read(0, rbuf, 512) <= 0) {
                    if (EWOULDBLOCK == errno)
                        (void) 0;
                    else if (EAGAIN == errno)
                        (void) 0;
                    else
                        break;
                }
            }

            if (EAGAIN == errno) {
                continue;
            }

            perror("msgrcv");
            break;
        }

        alarm(0);
        msg_handle(&rmsg, rlen, &smsg);

        if (msgsnd(smsgid, &smsg, diomsg::msg_snd_rcv_sz, 0) < 0) {
            perror("msgsnd");
            break;
        }
    }

    DEBUG(2) {
        fprintf(stderr, "%d diskd exiting\n", (int) mypid);
    }

    if (msgctl(rmsgid, IPC_RMID, 0) < 0)
        perror("msgctl IPC_RMID");

    if (msgctl(smsgid, IPC_RMID, 0) < 0)
        perror("msgctl IPC_RMID");

    if (shmdt(shmbuf) < 0)
        perror("shmdt");

    if (shmctl(shmid, IPC_RMID, 0) < 0)
        perror("shmctl IPC_RMID");

    return 0;
}

