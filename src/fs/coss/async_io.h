#ifndef __ASYNC_IO_H__
#define __ASYNC_IO_H__

#define MAX_ASYNCOP		128

typedef enum {
	AQ_STATE_NONE,		/* Not active/uninitialised */
	AQ_STATE_SETUP		/* Initialised */
} async_queue_state_t;

typedef enum {
	AQ_ENTRY_FREE,
	AQ_ENTRY_USED
} async_queue_entry_state_t;


typedef struct _async_queue_entry async_queue_entry_t;
typedef struct _async_queue async_queue_t;

/* An async queue entry */
struct _async_queue_entry {
	async_queue_entry_state_t aq_e_state;
	struct aiocb aq_e_queue[MAX_ASYNCOP];
	union {
		DRCB *read;
		DWCB *write;
	} callback;
	void *callback_data;
};

/* An async queue */
struct _async_queue {
	async_queue_state_t aq_state;
	async_queue_entry_t aq_queue;		/* queued operations */
	int aq_numpending;			/* Num of pending ops */
};


/* Functions */
extern void a_file_read(async_queue_t *q, int fd, void *buf, int req_len,
  off_t offset, DRCB *callback, void *data);
extern void a_file_write(async_queue_t *q, int fd, off_t offset, void *buf,
  int len, DWCB *callback, void *data, FREE *freefunc);
extern int a_file_callback(async_queue_t *q);
extern void a_file_setupqueue(async_queue_t *q);
extern void a_file_syncqueue(async_queue_t *q);
extern void a_file_closequeue(async_queue_t *q);

#endif
