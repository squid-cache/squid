/*
 * async_io.c - some quick async IO routines for COSS
 *
 * Adrian Chadd <adrian@squid-cache.org>
 *
 * These routines are simple plugin replacements for the file_* routines
 * in disk.c . They back-end into the POSIX AIO routines to provide
 * a nice and simple async IO framework for COSS.
 *
 * AIO is suitable for COSS - the only sync operations that the standard
 * supports are read/write, and since COSS works on a single file
 * per storedir it should work just fine.
 *
 * $Id: async_io.cc,v 1.11 2002/07/21 00:27:31 hno Exp $
 */

#include "squid.h"
#include <time.h>
#include <aio.h>

#include "async_io.h"

/*
 * For the time being, we kinda don't need to have our own
 * open/close. Just read/write (with the queueing), and callback
 * with the dequeueing)
 */


/* Internal routines */

/*
 * find a free aio slot.
 * Return the index, or -1 if we can't find one.
 */
static int
a_file_findslot(async_queue_t * q)
{
    int i;

    /* Later we should use something a little more .. efficient :) */
    for (i = 0; i < MAX_ASYNCOP; i++) {
	if (q->aq_queue[i].aq_e_state == AQ_ENTRY_FREE)
	    /* Found! */
	    return i;
    }
    /* found nothing */
    return -1;
}




/* Exported routines */

void
a_file_read(async_queue_t * q, int fd, void *buf, int req_len, off_t offset,
    DRCB * callback, void *data)
{
    int slot;
    async_queue_entry_t *qe;

    assert(q->aq_state == AQ_STATE_SETUP);

#if 0
    file_read(fd, buf, req_len, offset, callback, data);
#endif
    /* Find a free slot */
    slot = a_file_findslot(q);
    if (slot < 0) {
	/* No free slot? Callback error, and return */
	fatal("Aiee! out of aiocb slots!\n");
    }
    /* Mark slot as ours */
    qe = &q->aq_queue[slot];
    qe->aq_e_state = AQ_ENTRY_USED;
    qe->aq_e_callback.read = callback;
    qe->aq_e_callback_data = cbdataReference(data);
    qe->aq_e_type = AQ_ENTRY_READ;
    qe->aq_e_free = NULL;
    qe->aq_e_buf = buf;
    qe->aq_e_fd = fd;

    qe->aq_e_aiocb.aio_fildes = fd;
    qe->aq_e_aiocb.aio_nbytes = req_len;
    qe->aq_e_aiocb.aio_offset = offset;
    qe->aq_e_aiocb.aio_buf = buf;

    /* Account */
    q->aq_numpending++;

    /* Initiate aio */
    if (aio_read(&qe->aq_e_aiocb) < 0) {
	fatalf("Aiee! aio_read() returned error (%d)!\n", errno);
    }
}


void
a_file_write(async_queue_t * q, int fd, off_t offset, void *buf, int len,
    DWCB * callback, void *data, FREE * freefunc)
{
    int slot;
    async_queue_entry_t *qe;

    assert(q->aq_state == AQ_STATE_SETUP);

#if 0
    file_write(fd, offset, buf, len, callback, data, freefunc);
#endif
    /* Find a free slot */
    slot = a_file_findslot(q);
    if (slot < 0) {
	/* No free slot? Callback error, and return */
	fatal("Aiee! out of aiocb slots!\n");
    }
    /* Mark slot as ours */
    qe = &q->aq_queue[slot];
    qe->aq_e_state = AQ_ENTRY_USED;
    qe->aq_e_callback.write = callback;
    qe->aq_e_callback_data = cbdataReference(data);
    qe->aq_e_type = AQ_ENTRY_WRITE;
    qe->aq_e_free = freefunc;
    qe->aq_e_buf = buf;
    qe->aq_e_fd = fd;

    qe->aq_e_aiocb.aio_fildes = fd;
    qe->aq_e_aiocb.aio_nbytes = len;
    qe->aq_e_aiocb.aio_offset = offset;
    qe->aq_e_aiocb.aio_buf = buf;

    /* Account */
    q->aq_numpending++;

    /* Initiate aio */
    if (aio_write(&qe->aq_e_aiocb) < 0) {
	fatalf("Aiee! aio_read() returned error (%d)!\n", errno);
	assert(1 == 0);
    }
}


/*
 * Note: we grab the state and free the state before calling the callback
 * because this allows us to cut down the amount of time it'll take
 * to find a free slot (since if we call the callback first, we're going
 * to probably be allocated the slot _after_ this one..)
 *
 * I'll make it much more optimal later.
 */
int
a_file_callback(async_queue_t * q)
{
    int i;
    int completed = 0;
    int retval, reterr;
    DRCB *rc;
    DWCB *wc;
    FREE *freefunc;
    void *cbdata;
    int callback_valid;
    void *buf;
    int fd;
    async_queue_entry_t *aqe;
    async_queue_entry_type_t type;

    assert(q->aq_state == AQ_STATE_SETUP);

    /* Loop through all slots */
    for (i = 0; i < MAX_ASYNCOP; i++) {
	if (q->aq_queue[i].aq_e_state == AQ_ENTRY_USED) {
	    aqe = &q->aq_queue[i];
	    /* Active, get status */
	    reterr = aio_error(&aqe->aq_e_aiocb);
	    if (reterr < 0) {
		fatal("aio_error returned an error!\n");
	    }
	    if (reterr != EINPROGRESS) {
		/* Get the return code */
		retval = aio_return(&aqe->aq_e_aiocb);

		/* Get the callback parameters */
		freefunc = aqe->aq_e_free;
		rc = aqe->aq_e_callback.read;
		wc = aqe->aq_e_callback.write;
		buf = aqe->aq_e_buf;
		fd = aqe->aq_e_fd;
		type = aqe->aq_e_type;
		callback_valid = cbdataReferenceValidDone(aqe->aq_e_callback_data, &cbdata);

		/* Free slot */
		bzero(aqe, sizeof(async_queue_entry_t));
		aqe->aq_e_state = AQ_ENTRY_FREE;
		q->aq_numpending--;

		/* Callback */
		if (callback_valid) {
		    if (type == AQ_ENTRY_READ)
			rc(fd, buf, retval, reterr, cbdata);
		    if (type == AQ_ENTRY_WRITE)
			wc(fd, reterr, retval, cbdata);
		}
		if (type == AQ_ENTRY_WRITE && freefunc)
		    freefunc(buf);
	    }
	}
    }
    return completed;
}


void
a_file_setupqueue(async_queue_t * q)
{
    /* Make sure the queue isn't setup */
    assert(q->aq_state == AQ_STATE_NONE);

    /* Loop through, blanking the queue entries */

    /* Done */
    q->aq_state = AQ_STATE_SETUP;
}


void
a_file_syncqueue(async_queue_t * q)
{
    assert(q->aq_state == AQ_STATE_SETUP);

    /*
     * Keep calling callback to complete ops until the queue is empty
     * We can't quit when callback returns 0 - some calls may not
     * return any completed pending events, but they're still pending!
     */
    while (q->aq_numpending)
	a_file_callback(q);
}


void
a_file_closequeue(async_queue_t * q)
{
    assert(q->aq_state == AQ_STATE_SETUP);

    a_file_syncqueue(q);
    q->aq_state = AQ_STATE_NONE;
}
