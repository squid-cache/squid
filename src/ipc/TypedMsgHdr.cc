/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/TypedMsgHdr.h"
#include "SquidString.h"
#include "tools.h"

#include <cstring>

Ipc::TypedMsgHdr::TypedMsgHdr()
{
    clear();
    sync();
}

Ipc::TypedMsgHdr::TypedMsgHdr(const TypedMsgHdr &tmh)
{
    clear();
    operator =(tmh);
}

Ipc::TypedMsgHdr &Ipc::TypedMsgHdr::operator =(const TypedMsgHdr &tmh)
{
    if (this != &tmh) { // skip assignment to self
        memcpy(static_cast<msghdr*>(this), static_cast<const msghdr*>(&tmh), sizeof(msghdr));
        name = tmh.name;
        memcpy(&ios, &tmh.ios, sizeof(ios));
        data = tmh.data;
        ctrl = tmh.ctrl;
        offset = tmh.offset;
        sync();
    }
    return *this;
}

void
Ipc::TypedMsgHdr::clear()
{
    // may be called from the constructor, with object fields uninitialized
    memset(static_cast<msghdr*>(this), 0, sizeof(msghdr));
    memset(&name, 0, sizeof(name));
    memset(&ios, 0, sizeof(ios));
    data = DataBuffer();
    ctrl = CtrlBuffer();
    offset = 0;
}

// update msghdr and ios pointers based on msghdr counters
void Ipc::TypedMsgHdr::sync()
{
    if (msg_name) { // we have a name
        msg_name = &name;
    } else {
        Must(!msg_namelen && !msg_name);
    }

    if (msg_iov) { // we have a data component
        Must(msg_iovlen == 1);
        msg_iov = ios;
        ios[0].iov_base = &data;
        Must(ios[0].iov_len == sizeof(data));
    } else {
        Must(!msg_iovlen && !msg_iov);
    }

    if (msg_control) { // we have a control component
        Must(msg_controllen > 0);
        msg_control = &ctrl;
    } else {
        Must(!msg_controllen && !msg_control);
    }
    offset = 0;
}

int
Ipc::TypedMsgHdr::type() const
{
    Must(msg_iovlen == 1);
    return data.type_;
}

void
Ipc::TypedMsgHdr::address(const struct sockaddr_un& addr)
{
    allocName();
    name = addr;
    msg_name = &name;
    msg_namelen = SUN_LEN(&name);
}

void
Ipc::TypedMsgHdr::checkType(int destType) const
{
    Must(type() == destType);
}

void
Ipc::TypedMsgHdr::setType(int aType)
{
    if (data.type_) {
        Must(data.type_ == aType);
    } else {
        allocData();
        data.type_ = aType;
    }
}

int
Ipc::TypedMsgHdr::getInt() const
{
    int n = 0;
    getPod(n);
    return n;
}

void
Ipc::TypedMsgHdr::putInt(const int n)
{
    putPod(n);
}

void
Ipc::TypedMsgHdr::getString(String &s) const
{
    const int length = getInt();
    Must(length >= 0);
    // String uses memcpy uncoditionally; TODO: SBuf eliminates this check
    if (!length) {
        s.clean();
        return;
    }

    Must(length <= maxSize);
    // TODO: use SBuf.reserve() instead of a temporary buffer
    char buf[maxSize];
    getRaw(&buf, length);
    s.assign(buf, length);
}

void
Ipc::TypedMsgHdr::putString(const String &s)
{
    Must(s.psize() <= maxSize);
    putInt(s.psize());
    putRaw(s.rawBuf(), s.psize());
}

void
Ipc::TypedMsgHdr::getFixed(void *rawBuf, size_t rawSize) const
{
    // no need to load size because it is constant
    getRaw(rawBuf, rawSize);
}

void
Ipc::TypedMsgHdr::putFixed(const void *rawBuf, size_t rawSize)
{
    // no need to store size because it is constant
    putRaw(rawBuf, rawSize);
}

/// low-level loading of exactly size bytes of raw data
void
Ipc::TypedMsgHdr::getRaw(void *rawBuf, size_t rawSize) const
{
    if (rawSize > 0) {
        Must(rawSize <= data.size - offset);
        memcpy(rawBuf, data.raw + offset, rawSize);
        offset += rawSize;
    }
}

/// low-level storage of exactly size bytes of raw data
void
Ipc::TypedMsgHdr::putRaw(const void *rawBuf, size_t rawSize)
{
    if (rawSize > 0) {
        Must(rawSize <= sizeof(data.raw) - data.size);
        memcpy(data.raw + data.size, rawBuf, rawSize);
        data.size += rawSize;
    }
}

bool
Ipc::TypedMsgHdr::hasFd() const
{
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(this);
    return cmsg &&
           cmsg->cmsg_level == SOL_SOCKET &&
           cmsg->cmsg_type == SCM_RIGHTS;
}

void
Ipc::TypedMsgHdr::putFd(int fd)
{
    Must(fd >= 0);
    Must(!hasFd());
    allocControl();

    const int fdCount = 1;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(this);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fdCount);

    int *fdStore = reinterpret_cast<int*>(SQUID_CMSG_DATA(cmsg));
    memcpy(fdStore, &fd, fdCount * sizeof(int));
    msg_controllen = cmsg->cmsg_len;

    Must(hasFd());
}

int
Ipc::TypedMsgHdr::getFd() const
{
    Must(msg_control && msg_controllen);
    Must(hasFd());

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(this);
    Must(cmsg->cmsg_level == SOL_SOCKET);
    Must(cmsg->cmsg_type == SCM_RIGHTS);

    const int fdCount = 1;
    const int *fdStore = reinterpret_cast<const int*>(SQUID_CMSG_DATA(cmsg));
    int fd = -1;
    memcpy(&fd, fdStore, fdCount * sizeof(int));
    return fd;
}

void
Ipc::TypedMsgHdr::prepForReading()
{
    clear();
    // no sync() like other clear() calls because the
    // alloc*() below "sync()" the parts they allocate.
    allocName();
    allocData();
    allocControl();
}

/// initialize io vector with one io record
void
Ipc::TypedMsgHdr::allocData()
{
    Must(!msg_iovlen && !msg_iov);
    msg_iovlen = 1;
    msg_iov = ios;
    ios[0].iov_base = &data;
    ios[0].iov_len = sizeof(data);
    data.type_ = 0;
    data.size = 0;
}

void
Ipc::TypedMsgHdr::allocName()
{
    Must(!msg_name && !msg_namelen);
    msg_name = &name;
    msg_namelen = sizeof(name); // is that the right size?
}

void
Ipc::TypedMsgHdr::allocControl()
{
    Must(!msg_control && !msg_controllen);
    msg_control = &ctrl;
    msg_controllen = sizeof(ctrl);
}

