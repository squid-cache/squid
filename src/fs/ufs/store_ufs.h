/*
 * store_ufs.h
 *
 * Internal declarations for the ufs routines
 */

#ifndef __STORE_UFS_H__
#define __STORE_UFS_H__

struct _ufsinfo_t {
    int swaplog_fd;
    int l1;
    int l2;
    fileMap *map;
    int suggest;
};

struct _ufsstate_t {
    int fd;
    struct {
	unsigned int close_request:1;
	unsigned int reading:1;
	unsigned int writing:1;
    } flags;
};

typedef struct _ufsinfo_t ufsinfo_t;
typedef struct _ufsstate_t ufsstate_t;

/* The ufs_state memory pool */
extern MemPool *ufs_state_pool;

extern void storeUfsDirMapBitReset(SwapDir *, sfileno);
extern int storeUfsDirMapBitAllocate(SwapDir *);
extern char *storeUfsDirFullPath(SwapDir * SD, sfileno filn, char *fullpath);
extern void storeUfsDirUnlinkFile(SwapDir *, sfileno);
extern void storeUfsDirReplAdd(SwapDir * SD, StoreEntry *);
extern void storeUfsDirReplRemove(StoreEntry *);

/*
 * Store IO stuff
 */
extern STOBJCREATE storeUfsCreate;
extern STOBJOPEN storeUfsOpen;
extern STOBJCLOSE storeUfsClose;
extern STOBJREAD storeUfsRead;
extern STOBJWRITE storeUfsWrite;
extern STOBJUNLINK storeUfsUnlink;

#endif
