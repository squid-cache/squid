
#include "config.h"
#include "squid.h"


#include "store_diskd.h"

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

#undef assert
#include <assert.h>


#define STDERR_DEBUG 0

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

static int
do_open(diomsg * r, int len, const char *buf)
{
    int fd;
    file_state *fs;
    /*
     * note r->offset holds open() flags
     */
    fd = open(buf, r->offset, 0600);
    if (fd < 0) {
	fprintf(stderr, "%d %s: ", (int) mypid, buf);
	perror("open");
	return -errno;
    }
    fs = xcalloc(1, sizeof(*fs));
    fs->id = r->id;
    fs->key = &fs->id;		/* gack */
    fs->fd = fd;
    hash_join(hash, (hash_link *) fs);
#if STDERR_DEBUG
    fprintf(stderr, "%d OPEN  id %d, FD %d, fs %p\n",
	(int) mypid,
	fs->id,
	fs->fd,
	fs);
#endif
    return fd;
}

static int
do_close(diomsg * r, int len)
{
    int fd;
    file_state *fs;
    fs = (file_state *) hash_lookup(hash, &r->id);
    if (NULL == fs) {
	errno = EBADF;
	fprintf(stderr, "%d CLOSE id %d: ", (int) mypid, r->id);
	perror("do_close");
	return -EBADF;
    }
    fd = fs->fd;
    hash_remove_link(hash, (hash_link *) fs);
#if STDERR_DEBUG
    fprintf(stderr, "%d CLOSE id %d, FD %d, fs %p\n",
	(int) mypid,
	r->id,
	fs->fd,
	fs);
#endif
    xfree(fs);
    return close(fd);
}

static int
do_read(diomsg * r, int len, char *buf)
{
    int x;
    int readlen = r->size;
    file_state *fs;
    fs = (file_state *) hash_lookup(hash, &r->id);
    if (NULL == fs) {
	errno = EBADF;
	fprintf(stderr, "%d READ  id %d: ", (int) mypid, r->id);
	perror("do_read");
	return -EBADF;
    }
    if (r->offset > -1 && r->offset != fs->offset) {
#if STDERR_DEBUG
	fprintf(stderr, "seeking to %d\n", r->offset);
#endif
	if (lseek(fs->fd, r->offset, SEEK_SET) < 0) {
	    fprintf(stderr, "%d FD %d, offset %d: ", (int) mypid, fs->fd, r->offset);
	    perror("lseek");
	}
    }
    x = read(fs->fd, buf, readlen);
#if STDERR_DEBUG
    fprintf(stderr, "%d READ %d,%d,%d ret %d\n", (int) mypid,
	fs->fd, readlen, r->offset, x);
#endif
    if (x < 0) {
	fprintf(stderr, "%d FD %d: ", (int) mypid, fs->fd);
	perror("read");
	return -errno;
    }
    fs->offset = r->offset + x;
    return x;
}

static int
do_write(diomsg * r, int len, const char *buf)
{
    int wrtlen = r->size;
    int x;
    file_state *fs;
    fs = (file_state *) hash_lookup(hash, &r->id);
    if (NULL == fs) {
	errno = EBADF;
	fprintf(stderr, "%d WRITE id %d: ", (int) mypid, r->id);
	perror("do_write");
	return -EBADF;
    }
    if (r->offset > -1 && r->offset != fs->offset) {
	if (lseek(fs->fd, r->offset, SEEK_SET) < 0) {
	    fprintf(stderr, "%d FD %d, offset %d: ", (int) mypid, fs->fd, r->offset);
	    perror("lseek");
	}
    }
#if STDERR_DEBUG
    fprintf(stderr, "%d WRITE %d,%d,%d\n", (int) mypid,
	fs->fd, wrtlen, r->offset);
#endif
    x = write(fs->fd, buf, wrtlen);
    if (x < 0) {
	fprintf(stderr, "%d FD %d: ", (int) mypid, fs->fd);
	perror("write");
	return -errno;
    }
    fs->offset = r->offset + x;
    return x;
}

static int
do_unlink(diomsg * r, int len, const char *buf)
{
    if (truncate(buf, 0) < 0) {
	fprintf(stderr, "%d UNLNK id %d %s: ", (int) mypid, r->id, buf);
	perror("truncate");
	return -errno;
    }
#if STDERR_DEBUG
    fprintf(stderr, "%d UNLNK %s\n", (int) mypid, buf);
#endif
    return 0;
}

static void
msg_handle(diomsg * r, int rl, diomsg * s)
{
    char *buf = NULL;
    s->mtype = r->mtype;
    s->callback_data = r->callback_data;
    s->shm_offset = r->shm_offset;
    s->id = r->id;
    if (s->shm_offset > -1)
	buf = shmbuf + s->shm_offset;
    switch (r->mtype) {
    case _MQD_OPEN:
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

int
fsCmp(const void *a, const void *b)
{
    const int *A = a;
    const int *B = b;
    return *A != *B;
}

unsigned int
fsHash(const void *key, unsigned int n)
{
    /* note, n must be a power of 2! */
    const int *k = key;
    return (*k & (--n));
}

static void
alarm_handler(int sig)
{
    (void) 0;
}

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
    shmbuf = shmat(shmid, NULL, 0);
    if (shmbuf == (void *) -1) {
	perror("shmat");
	return 1;
    }
    hash = hash_create(fsCmp, 1 << 4, fsHash);
    assert(hash);
    fcntl(0, F_SETFL, SQUID_NONBLOCK);
    memset(&sa, '\0', sizeof(sa));
    sa.sa_handler = alarm_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, NULL);
    for (;;) {
	alarm(1);
	memset(&rmsg, '\0', sizeof(rmsg));
	rlen = msgrcv(rmsgid, &rmsg, msg_snd_rcv_sz, 0, 0);
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
	if (msgsnd(smsgid, &smsg, msg_snd_rcv_sz, 0) < 0) {
	    perror("msgsnd");
	    break;
	}
    }
#if STDERR_DEBUG
    fprintf(stderr, "%d diskd exiting\n", (int) mypid);
#endif
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

