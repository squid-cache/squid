/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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

#ifndef SQUID_DIOMSG_H__
#define SQUID_DIOMSG_H__

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

#endif /* SQUID_DIOMSG_H__ */

