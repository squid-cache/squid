/*
 * store_ufs.h
 *
 * Internal declarations for the ufs routines
 */

#ifndef __STORE_UFS_H__
#define __STORE_UFS_H__

struct _ufsstate_t {
    int fd;
    struct {
	unsigned int close_request:1;
	unsigned int reading:1;
	unsigned int writing:1;
    } flags;
};

typedef struct _ufsstate_t ufsstate_t;

/* The ufs_state memory pool */
extern MemPool *ufs_state_pool;

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
