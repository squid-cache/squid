/*
 * diomsg.h
 *
 * Internal declarations for the diskd routines
 */

#ifndef __SQUID_DIOMSG_H__
#define __SQUID_DIOMSG_H__

enum {
    _MQD_NOP,
    _MQD_OPEN,
    _MQD_CREATE,
    _MQD_CLOSE,
    _MQD_READ,
    _MQD_WRITE,
    _MQD_UNLINK
};

struct RefCountable_;

struct diomsg
{
    mtyp_t mtype;
    int id;
    int seq_no;
    void * callback_data;
    RefCountable_ * requestor;
    int size;
    int offset;
    int status;
    bool newstyle;
    int shm_offset;
    static const int msg_snd_rcv_sz;
};


#endif
