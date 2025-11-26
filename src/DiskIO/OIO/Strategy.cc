/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/OIO/File.h"
#include "DiskIO/OIO/Strategy.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"

DiskIO::OIO::Strategy::Strategy()
{
    aq.aq_state = AQ_STATE_NONE;
    aq.aq_numpending = 0;
    memset(&aq.aq_queue, 0, sizeof(aq.aq_queue));
}

DiskIO::OIO::Strategy::~Strategy()
{
    assert(aq.aq_state == AQ_STATE_SETUP || aq.aq_numpending == 0);
    sync();
    aq.aq_state = AQ_STATE_NONE;
}

int
DiskIO::OIO::Strategy::load()
{
    return aq.aq_numpending * 1000 / MAX_ASYNCOP;
}

RefCount<DiskFile>
DiskIO::OIO::Strategy::newFile(char const *path)
{
    return new File(path, this);
}

void
DiskIO::OIO::Strategy::sync()
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

void
DiskIO::OIO::Strategy::init()
{
    /* Make sure the queue isn't setup */
    assert(aq.aq_state == AQ_STATE_NONE);

    /* Loop through, blanking the queue entries */

    /* Done */
    aq.aq_state = AQ_STATE_SETUP;
}

int
DiskIO::OIO::Strategy::findSlot()
{
    /* Later we should use something a little more .. efficient :) */
    for (int i = 0; i < MAX_ASYNCOP; ++i) {
        if (aq.aq_queue[i].aq_e_state == AQ_ENTRY_FREE)
            return i;
    }

    return -1;
}
