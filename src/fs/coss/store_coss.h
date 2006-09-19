#ifndef __COSS_H__
#define __COSS_H__

#include "SwapDir.h"

#ifndef COSS_MEMBUF_SZ
#define	COSS_MEMBUF_SZ	1048576
#endif

/* Note that swap_filen in sio/e are actually disk offsets too! */

/* What we're doing in storeCossAllocate() */
#define COSS_ALLOC_NOTIFY		0
#define COSS_ALLOC_ALLOCATE		1
#define COSS_ALLOC_REALLOC		2

class CossSwapDir;

class CossMemBuf
{

public:
    void describe(int level, int line);
    void maybeWrite(CossSwapDir * SD);
    void write(CossSwapDir * SD);
    dlink_node node;
    size_t diskstart;		/* in blocks */
    size_t diskend;		/* in blocks */
    CossSwapDir *SD;
    int lockcount;
    char buffer[COSS_MEMBUF_SZ];

    struct _cossmembuf_flags
    {
        unsigned int full:1;
        unsigned int writing:1;
    } flags;
};

struct _cossindex
{
    /* Note: the dlink_node MUST be the first member of the structure.
     * This member is later pointer typecasted to coss_index_node *.
     */
    dlink_node node;
};



/* Per-storeiostate info */

class CossState : public StoreIOState
{

public:
    MEMPROXY_CLASS(CossState);
    CossState(CossSwapDir *);
    ~CossState();

    char *readbuffer;
    char *requestbuf;
    size_t requestlen;
    size_t requestoffset;	/* in blocks */
    sfileno reqdiskoffset;	/* in blocks */

    struct
    {

unsigned int reading:
        1;

unsigned int writing:
        1;
    }

    flags;

    CossMemBuf *locked_membuf;
    size_t st_size;
    void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data);
    void write(char const *buf, size_t size, off_t offset, FREE * free_func);
    void close();
    void doCallback(int errflag);
    void lockMemBuf();

    CossSwapDir *SD;
};

MEMPROXY_CLASS_INLINE(CossState)

typedef struct _cossindex CossIndexNode;

/* Whether the coss system has been setup or not */
extern int coss_initialised;
extern MemAllocator *coss_membuf_pool;
extern MemAllocator *coss_index_pool;

#include "DiskIO/ReadRequest.h"

class CossRead : public ReadRequest
{

public:
    void * operator new (size_t);
    void operator delete (void *);
    CossRead(ReadRequest const &base, StoreIOState::Pointer anSio) : ReadRequest(base) , sio(anSio) {}

    StoreIOState::Pointer sio;

private:
    CBDATA_CLASS(CossRead);
};

#include "DiskIO/WriteRequest.h"

class CossWrite : public WriteRequest
{

public:
    void * operator new (size_t);
    void operator delete (void *);
    CossWrite(WriteRequest const &base, CossMemBuf *aBuf) : WriteRequest(base) , membuf(aBuf) {}

    CossMemBuf *membuf;

private:
    CBDATA_CLASS(CossWrite);
};

#endif
