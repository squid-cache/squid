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
 * $Id: async_io.cc,v 1.2 2001/08/12 14:02:01 adrian Exp $
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
a_file_findslot(async_queue_t *q)
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
a_file_read(async_queue_t *q, int fd, void *buf, int req_len, off_t offset,
  DRCB *callback, void *data)
{
	assert(q->aq_state == AQ_STATE_SETUP);

#if 0
	file_read(fd, buf, req_len, offset, callback, data);
#endif
	/* Find a free slot */
		/* No free slot? Callback error, and return */

	/* Mark slot as ours */
	/* Initiate aio */
}


void
a_file_write(async_queue_t *q, int fd, off_t offset, void *buf, int len,
  DWCB *callback, void *data, FREE *freefunc)
{
	assert(q->aq_state == AQ_STATE_SETUP);

#if 0
	file_write(fd, offset, buf, len, callback, data, freefunc);
#endif
	/* Find a free slot */
		/* No free slot? Callback error, and return */
	/* Mark slot as ours */
	/* Initiate aio */
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
a_file_callback(async_queue_t *q)
{
	assert(q->aq_state == AQ_STATE_SETUP);

	/* Loop through all slots */
		/* Active, get status */
			/* Ready? Grab the state locally */
			/* Free the state */
			/* Call callback */


	return 0;
}


void
a_file_setupqueue(async_queue_t *q)
{
	int i;

	/* Make sure the queue isn't setup */
	assert(q->aq_state == AQ_STATE_NONE);

	/* Loop through, blanking the queue entries */

	/* Done */
	q->aq_state = AQ_STATE_SETUP;

}


void
a_file_syncqueue(async_queue_t *q)
{
	assert(q->aq_state == AQ_STATE_SETUP);

	/* Good point? :-) */
}


void
a_file_closequeue(async_queue_t *q)
{
	assert(q->aq_state == AQ_STATE_SETUP);

	a_file_syncqueue(q);
	q->aq_state = AQ_STATE_NONE;
}

