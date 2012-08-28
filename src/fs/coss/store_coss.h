#ifndef __COSS_H__
#define __COSS_H__

#include "SwapDir.h"

#ifndef COSS_MEMBUF_SZ
#define	COSS_MEMBUF_SZ	1048576
#endif

/** \note  swap_filen in sio/e are actually disk offsets too! */

/** What we're doing in storeCossAllocate() */
#define COSS_ALLOC_NOTIFY		0

/** What we're doing in storeCossAllocate() */
#define COSS_ALLOC_ALLOCATE		1

/** What we're doing in storeCossAllocate() */
#define COSS_ALLOC_REALLOC		2

class CossSwapDir;

/// \ingroup COSS
class CossMemBuf
{

public:
    void describe(int level, int line);
    void maybeWrite(CossSwapDir * SD);
    void write(CossSwapDir * SD);
    dlink_node node;
    off_t diskstart;		/* in blocks */
    off_t diskend;		/* in blocks */
    CossSwapDir *SD;
    int lockcount;
    char buffer[COSS_MEMBUF_SZ];

    struct _cossmembuf_flags {
        unsigned int full:1;
        unsigned int writing:1;
    } flags;
};

/// \ingroup COSS
struct _cossindex {
    /**
     \note The dlink_node MUST be the first member of the structure.
     *     This member is later pointer typecasted to coss_index_node *.
     */
    dlink_node node;
};

/**
 \ingroup COSS
 * Per-storeiostate info
 */
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
    int64_t reqdiskoffset;	/* in blocks */

    struct {
        unsigned int reading:1;
        unsigned int writing:1;
    } flags;

    CossMemBuf *locked_membuf;
    off_t st_size;
    void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data);
    void write(char const *buf, size_t size, off_t offset, FREE * free_func);
    virtual void close(int);
    void doCallback(int errflag);
    void lockMemBuf();

    CossSwapDir *SD;
};

MEMPROXY_CLASS_INLINE(CossState);

/// \ingroup COSS
typedef struct _cossindex CossIndexNode;

/**
 \ingroup COSS
 * Whether the coss system has been setup or not
 */
extern int coss_initialised;
/// \ingroup COSS
extern MemAllocator *coss_membuf_pool;
/// \ingroup COSS
extern MemAllocator *coss_index_pool;

#include "DiskIO/ReadRequest.h"

/// \ingroup COSS
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

/// \ingroup COSS
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
