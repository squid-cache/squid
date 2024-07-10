/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * diomsg.h
 *
 * Internal declarations for the diskd routines
 */

#ifndef SQUID_SRC_DISKIO_DISKDAEMON_DIOMSG_H
#define SQUID_SRC_DISKIO_DISKDAEMON_DIOMSG_H

enum {
    _MQD_NOP,
    _MQD_OPEN,
    _MQD_CREATE,
    _MQD_CLOSE,
    _MQD_READ,
    _MQD_WRITE,
    _MQD_UNLINK
};

class Lock;

struct diomsg {
    mtyp_t mtype;
    int id;
    int seq_no;
    void * callback_data;
    Lock * requestor;
    size_t size;
    off_t offset;
    int status;
    bool newstyle;
    int shm_offset;
    static const int msg_snd_rcv_sz;
};

#endif /* SQUID_SRC_DISKIO_DISKDAEMON_DIOMSG_H */

