/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_TYPED_MSG_HDR_H
#define SQUID_IPC_TYPED_MSG_HDR_H

#include "compat/cmsg.h"
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

class String;

namespace Ipc
{

/// struct msghdr with a known type, fixed-size I/O and control buffers
class TypedMsgHdr: public msghdr
{
public:
    enum {maxSize = 4096};

public:
    TypedMsgHdr();
    TypedMsgHdr(const TypedMsgHdr &tmh);
    TypedMsgHdr &operator =(const TypedMsgHdr &tmh);

    void address(const struct sockaddr_un &addr); ///< sets [dest.] address

    /* message type manipulation; these must be called before put/get*() */
    void setType(int aType); ///< sets message type; use MessageType enum
    void checkType(int aType) const; ///< throws if stored type is not aType
    int type() const; ///< returns stored type or zero if none

    /* access for Plain Old Data (POD)-based message parts */
    template <class Pod>
    void getPod(Pod &pod) const { getFixed(&pod, sizeof(pod)); } ///< load POD
    template <class Pod>
    void putPod(const Pod &pod) { putFixed(&pod, sizeof(pod)); } ///< store POD

    /* access to message parts for selected commonly-used part types */
    void getString(String &s) const; ///< load variable-length string
    void putString(const String &s); ///< store variable-length string
    int getInt() const; ///< load an integer
    void putInt(int n); ///< store an integer
    void getFixed(void *raw, size_t size) const; ///< always load size bytes
    void putFixed(const void *raw, size_t size); ///< always store size bytes

    /// returns true if there is data to extract; handy for optional parts
    bool hasMoreData() const { return offset < data.size; }

    /* access to a "file" descriptor that can be passed between processes */
    void putFd(int aFd); ///< stores descriptor
    int getFd() const; ///< returns stored descriptor
    bool hasFd() const; ///< whether the message has a descriptor stored

    /* raw, type-independent access for I/O */
    void prepForReading(); ///< reset and provide all buffers
    char *raw() { return reinterpret_cast<char*>(this); }
    const char *raw() const { return reinterpret_cast<const char*>(this); }
    size_t size() const { return sizeof(*this); } ///< not true message size

private:
    void sync();
    void allocData();
    void allocName();
    void allocControl();

    /* raw, type-independent manipulation used by type-specific methods */
    void getRaw(void *raw, size_t size) const;
    void putRaw(const void *raw, size_t size);

private:
    struct sockaddr_un name; ///< same as .msg_name

    struct iovec ios[1]; ///< same as .msg_iov[]

    struct DataBuffer {
        int type_; ///< Message kind, uses MessageType values
        size_t size; ///< actual raw data size (for sanity checks)
        char raw[maxSize]; ///< buffer with type-specific data
    } data; ///< same as .msg_iov[0].iov_base

    struct CtrlBuffer {
        /// control buffer space for one fd
        char raw[SQUID_CMSG_SPACE(sizeof(int))];
    } ctrl; ///< same as .msg_control

    /// data offset for the next get/put*() to start with
    mutable unsigned int offset;
};

} // namespace Ipc

#endif /* SQUID_IPC_TYPED_MSG_HDR_H */

