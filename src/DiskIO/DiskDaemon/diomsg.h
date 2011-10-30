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

struct RefCountable_;

struct diomsg {
    mtyp_t mtype;
    int id;
    int seq_no;
    void * callback_data;
    RefCountable_ * requestor;
    size_t size;
    off_t offset;
    int status;
    bool newstyle;
    int shm_offset;
    static const int msg_snd_rcv_sz;
};

#endif /* SQUID_DIOMSG_H__ */
