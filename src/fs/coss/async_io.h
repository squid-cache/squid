#ifndef __ASYNC_IO_H__
#define __ASYNC_IO_H__
#include <aio.h>

#define MAX_ASYNCOP		128

typedef enum {
    AQ_STATE_NONE,		/* Not active/uninitialised */
    AQ_STATE_SETUP		/* Initialised */
} async_queue_state_t;

typedef enum {
    AQ_ENTRY_FREE,
    AQ_ENTRY_USED
} async_queue_entry_state_t;

typedef enum {
    AQ_ENTRY_NONE,
    AQ_ENTRY_READ,
    AQ_ENTRY_WRITE
} async_queue_entry_type_t;


typedef struct _async_queue_entry async_queue_entry_t;

typedef struct _async_queue async_queue_t;

/* An async queue entry */

struct _async_queue_entry
{
    async_queue_entry_state_t aq_e_state;
    async_queue_entry_type_t aq_e_type;

    struct aiocb aq_e_aiocb;
    union {
        DRCB *read;
        DWCB *write;
    } aq_e_callback;
    void *aq_e_callback_data;
    FREE *aq_e_free;
    int aq_e_fd;
    void *aq_e_buf;
};

/* An async queue */

struct _async_queue
{
    async_queue_state_t aq_state;
    async_queue_entry_t aq_queue[MAX_ASYNCOP];	/* queued ops */
    int aq_numpending;		/* Num of pending ops */
};


/* Functions */
extern void a_file_read(async_queue_t * q, int fd, void *buf, int req_len,
                            off_t offset, DRCB * callback, void *data);
extern void a_file_write(async_queue_t * q, int fd, off_t offset, void *buf,
                             int len, DWCB * callback, void *data, FREE * freefunc);
extern int a_file_callback(async_queue_t * q);
extern void a_file_setupqueue(async_queue_t * q);
extern void a_file_syncqueue(async_queue_t * q);
extern void a_file_closequeue(async_queue_t * q);

#endif
