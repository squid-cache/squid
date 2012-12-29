
/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */
/*
 * Author: Adrian Chadd <adrian@squid-cache.org>
 *
 * These routines are simple plugin replacements for the file_* routines
 * in disk.c . They back-end into the POSIX AIO routines to provide
 * a nice and simple async IO framework for COSS.
 *
 * AIO is suitable for COSS - the only sync operations that the standard
 * supports are read/write, and since COSS works on a single file
 * per storedir it should work just fine.
 */

#include "squid.h"
#include "AIODiskIOStrategy.h"
#include "AIODiskFile.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"

AIODiskIOStrategy::AIODiskIOStrategy() :
        fd(-1)
{
    aq.aq_state = AQ_STATE_NONE;
    aq.aq_numpending = 0;
    memset(&aq.aq_queue, 0, sizeof(aq.aq_queue));
}

AIODiskIOStrategy::~AIODiskIOStrategy()
{
    assert(aq.aq_state == AQ_STATE_SETUP ||
           aq.aq_numpending == 0);

    sync();
    aq.aq_state = AQ_STATE_NONE;
}

bool
AIODiskIOStrategy::shedLoad()
{
    return false;
}

int
AIODiskIOStrategy::load()
{
    return aq.aq_numpending * 1000 / MAX_ASYNCOP;
}

RefCount<DiskFile>
AIODiskIOStrategy::newFile (char const *path)
{
    if (shedLoad()) {
        return NULL;
    }

    return new AIODiskFile (path, this);
}

void
AIODiskIOStrategy::sync()
{
    assert(aq.aq_state == AQ_STATE_SETUP);

    /*
     * Keep calling callback to complete ops until the queue is empty
     * We can't quit when callback returns 0 - some calls may not
     * return any completed pending events, but they're still pending!
     */

    while (aq.aq_numpending)
        callback();
}

bool
AIODiskIOStrategy::unlinkdUseful() const
{
    return false;
}

void
AIODiskIOStrategy::unlinkFile (char const *)
{}

/*
 * Note: we grab the state and free the state before calling the callback
 * because this allows us to cut down the amount of time it'll take
 * to find a free slot (since if we call the callback first, we're going
 * to probably be allocated the slot _after_ this one..)
 *
 * I'll make it much more optimal later.
 */
int
AIODiskIOStrategy::callback()
{
    return 0;
    int i;
    int completed = 0;
    int retval, reterr;
    FREE *freefunc;
    void *cbdata;
    int callback_valid;
    void *buf;
    async_queue_entry_t *aqe;
    async_queue_entry_type_t type;

    assert(aq.aq_state == AQ_STATE_SETUP);

    /* Loop through all slots */

    for (i = 0; i < MAX_ASYNCOP; ++i) {
        if (aq.aq_queue[i].aq_e_state == AQ_ENTRY_USED) {
            aqe = &aq.aq_queue[i];
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
                buf = aqe->aq_e_buf;
                type = aqe->aq_e_type;
                callback_valid = cbdataReferenceValidDone(aqe->aq_e_callback_data, &cbdata);
                AIODiskFile * theFile = NULL;
                void *theFileVoid = NULL;
                void *theTmpFile = aqe->theFile;
                bool fileOk = cbdataReferenceValidDone(theTmpFile, &theFileVoid);

                if (fileOk) {
                    theFile = static_cast<AIODiskFile *>(theFileVoid);
                }

                /* Free slot */
                memset(aqe, 0, sizeof(async_queue_entry_t));

                aqe->aq_e_state = AQ_ENTRY_FREE;

                --aq.aq_numpending;

                /* Callback */

                if (callback_valid) {
                    assert (fileOk);

                    if (type == AQ_ENTRY_READ)
                        theFile->ioRequestor->readCompleted((const char *)buf, retval, reterr, static_cast<ReadRequest *>(cbdata));

                    if (type == AQ_ENTRY_WRITE)
                        theFile->ioRequestor->writeCompleted(reterr,retval, static_cast<WriteRequest *>(cbdata));
                }

                if (type == AQ_ENTRY_WRITE && freefunc)
                    freefunc(buf);
            }
        }
    }

    return completed;
}

void
AIODiskIOStrategy::init()
{
    /* Make sure the queue isn't setup */
    assert(aq.aq_state == AQ_STATE_NONE);

    /* Loop through, blanking the queue entries */

    /* Done */
    aq.aq_state = AQ_STATE_SETUP;
}

void
AIODiskIOStrategy::statfs(StoreEntry & sentry)const
{}

ConfigOption *
AIODiskIOStrategy::getOptionTree() const
{
    return NULL;
}

/*
 * find a free aio slot.
 * Return the index, or -1 if we can't find one.
 */
int
AIODiskIOStrategy::findSlot()
{
    /* Later we should use something a little more .. efficient :) */

    for (int i = 0; i < MAX_ASYNCOP; ++i) {
        if (aq.aq_queue[i].aq_e_state == AQ_ENTRY_FREE)
            /* Found! */
            return i;
    }

    /* found nothing */
    return -1;
}
