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
 * $Id: async_io.cc,v 1.1 2001/08/12 10:20:41 adrian Exp $
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

void
a_file_read(async_queue_t *q, int fd, void *buf, int req_len, off_t offset,
  DRCB *callback, void *data)
{
	assert(q->aq_state == AQ_STATE_SETUP);

	file_read(fd, buf, req_len, offset, callback, data);
}


void
a_file_write(async_queue_t *q, int fd, off_t offset, void *buf, int len,
  DWCB *callback, void *data, FREE *freefunc)
{
	assert(q->aq_state == AQ_STATE_SETUP);

	file_write(fd, offset, buf, len, callback, data, freefunc);
}


int
a_file_callback(async_queue_t *q)
{
	assert(q->aq_state == AQ_STATE_SETUP);

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

}


void
a_file_closequeue(async_queue_t *q)
{
	assert(q->aq_state == AQ_STATE_SETUP);

	a_file_syncqueue(q);
	q->aq_state = AQ_STATE_NONE;
}

