/*
 * store_aufs.h
 *
 * Internal declarations for the aufs routines
 */

#ifndef __STORE_ASYNCUFS_H__
#define __STORE_ASYNCUFS_H__

#ifdef AUFS_IO_THREADS
#define NUMTHREADS AUFS_IO_THREADS
#else
#define NUMTHREADS (Config.cacheSwap.n_configured*16)
#endif

/* Queue limit where swapouts are deferred (load calculation) */
#define MAGIC1 (NUMTHREADS*Config.cacheSwap.n_configured*5)
/* Queue limit where swapins are deferred (open/create fails) */
#define MAGIC2 (NUMTHREADS*Config.cacheSwap.n_configured*20)

/* Which operations to run async */
#define ASYNC_OPEN 1
#define ASYNC_CLOSE 0
#define ASYNC_CREATE 1
#define ASYNC_WRITE 0
#define ASYNC_READ 1

enum _squidaio_request_type {
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
typedef enum _squidaio_request_type squidaio_request_type;

struct _squidaio_result_t {
    int aio_return;
    int aio_errno;
    enum _squidaio_request_type result_type;
    void *_data;		/* Internal housekeeping */
    void *data;			/* Available to the caller */
};

typedef struct _squidaio_result_t squidaio_result_t;

typedef void AIOCB(int fd, void *cbdata, const char *buf, int aio_return, int aio_errno);

int squidaio_cancel(squidaio_result_t *);
int squidaio_open(const char *, int, mode_t, squidaio_result_t *);
int squidaio_read(int, char *, int, off_t, int, squidaio_result_t *);
int squidaio_write(int, char *, int, off_t, int, squidaio_result_t *);
int squidaio_close(int, squidaio_result_t *);
int squidaio_stat(const char *, struct stat *, squidaio_result_t *);
int squidaio_unlink(const char *, squidaio_result_t *);
int squidaio_truncate(const char *, off_t length, squidaio_result_t *);
int squidaio_opendir(const char *, squidaio_result_t *);
squidaio_result_t *squidaio_poll_done(void);
int squidaio_operations_pending(void);
int squidaio_sync(void);
int squidaio_get_queue_len(void);
void *squidaio_xmalloc(int size);
void squidaio_xfree(void *p, int size);

void aioInit(void);
void aioDone(void);
void aioCancel(int);
void aioOpen(const char *, int, mode_t, AIOCB *, void *);
void aioClose(int);
void aioWrite(int, int offset, char *, int size, AIOCB *, void *, FREE *);
void aioRead(int, int offset, int size, AIOCB *, void *);
void aioStat(char *, struct stat *, AIOCB *, void *);
void aioUnlink(const char *, AIOCB *, void *);
void aioTruncate(const char *, off_t length, AIOCB *, void *);
int aioQueueSize(void);

#include "ufscommon.h"

class AufsIO;
class AUFSFile : public DiskFile {
  public:
    virtual void deleteSelf() const;
    void * operator new (size_t);
    void operator delete (void *);
    AUFSFile (char const *path, AufsIO *);
    ~AUFSFile();
    virtual void open (int, mode_t, IORequestor::Pointer);
    virtual void create (int, mode_t, IORequestor::Pointer);
    virtual void read(char *, off_t, size_t);
    virtual void write(char const *buf, size_t size, off_t offset, FREE *free_func);
    void close();
    virtual bool error() const;
    virtual int getFD() const { return fd;}
    virtual bool canRead() const;
    virtual bool canWrite() const;
  private:
#if ASYNC_READ
static AIOCB ReadDone;
#else
static DRCB ReadDone;
#endif
#if ASYNC_WRITE
static AIOCB WriteDone;
#else
static DWCB WriteDone;
#endif
    int fd;
    bool errorOccured;
    char const *path_;
    AufsIO* IO;
    static AIOCB OpenDone;
    void openDone(int fd, const char *buf, int aio_return, int aio_errno);
    IORequestor::Pointer ioRequestor;
    CBDATA_CLASS(AUFSFile);
    void doClose();
    
    void readDone(int fd, const char *buf, int len, int errflag);
    void writeDone (int fd, int errflag, size_t len);
};

class squidaiostate_t : public UFSStoreState {
  public:
    virtual void deleteSelf() const {delete this;}
    void * operator new (size_t);
    void operator delete (void *);
    squidaiostate_t(SwapDir *, StoreEntry *, STIOCB *, void *);
    ~squidaiostate_t();

    void close();
    int fd;
    struct {
	unsigned int write_kicking:1;
	unsigned int read_kicking:1;
	unsigned int inreaddone:1;
    } flags;
    void ioCompletedNotification();
    void closeCompleted();
    void readCompleted(const char *buf, int len, int errflag);
    void writeCompleted(int errflag, size_t len);
    void writeDone(int fd, int errflag, size_t len);
  private:
    CBDATA_CLASS(squidaiostate_t);
    void openDone();
};

/*
 * Store IO stuff
 */
#include "SwapDir.h"
class AUFSSwapDir : public UFSSwapDir
{
public:
  virtual void dump(StoreEntry &)const;
  virtual void unlink(StoreEntry &);
  virtual int canStore(StoreEntry const &)const;
  virtual int callback();
  virtual void sync();
  virtual void parse (int index, char *path);
  virtual void reconfigure(int, char *);
  virtual void unlinkFile(char const *);
};

class AufsIO : public UFSStrategy
{
public:
   virtual bool shedLoad();
   virtual void deleteSelf() const;
   virtual StoreIOState::Pointer createState(SwapDir *SD, StoreEntry *e, STIOCB * callback, void *callback_data) const;
   virtual DiskFile::Pointer newFile(char const *path);
   static AufsIO Instance;
};

#endif
