/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include <string.h>
#include "TextException.h"
#include "ipc/TypedMsgHdr.h"

Ipc::TypedMsgHdr::TypedMsgHdr()
{
	xmemset(this, 0, sizeof(*this));
	sync();
}

Ipc::TypedMsgHdr::TypedMsgHdr(const TypedMsgHdr &tmh)
{
	xmemcpy(this, &tmh, sizeof(*this));
	sync();
}

Ipc::TypedMsgHdr &Ipc::TypedMsgHdr::operator =(const TypedMsgHdr &tmh)
{
	if (this != &tmh) { // skip assignment to self
		xmemcpy(this, &tmh, sizeof(*this));
		sync();
	}
	return *this;
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
Ipc::TypedMsgHdr::getData(int destType, void *raw, size_t size) const
{
	Must(type() == destType);
	Must(size == data.size);
	xmemcpy(raw, data.raw, size);
}

void
Ipc::TypedMsgHdr::putData(int aType, const void *raw, size_t size)
{
	Must(size <= sizeof(data.raw));
	allocData();
	data.type_ = aType;
	data.size = size;
	xmemcpy(data.raw, raw, size);
}

void
Ipc::TypedMsgHdr::putFd(int fd)
{
	Must(fd >= 0);
	allocControl();

	const int fdCount = 1;

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(this);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fdCount);

    int *fdStore = reinterpret_cast<int*>(CMSG_DATA(cmsg));
	xmemcpy(fdStore, &fd, fdCount * sizeof(int));
    msg_controllen = cmsg->cmsg_len;
}

int
Ipc::TypedMsgHdr::getFd() const
{
	Must(msg_control && msg_controllen);

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(this);
	Must(cmsg->cmsg_level == SOL_SOCKET);
	Must(cmsg->cmsg_type == SCM_RIGHTS);

	const int fdCount = 1;
    const int *fdStore = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
	int fd = -1;
	xmemcpy(&fd, fdStore, fdCount * sizeof(int));
	return fd;
}

void
Ipc::TypedMsgHdr::prepForReading()
{
	xmemset(this, 0, sizeof(*this));
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
