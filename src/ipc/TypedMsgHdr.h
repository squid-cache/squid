/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_TYPED_MSG_HDR_H
#define SQUID_IPC_TYPED_MSG_HDR_H

#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

namespace Ipc
{

/// struct msghdr with a known type, fixed-size I/O and control buffers
class TypedMsgHdr: public msghdr
{
public:
    TypedMsgHdr();
    TypedMsgHdr(const TypedMsgHdr &tmh);
    TypedMsgHdr &operator =(const TypedMsgHdr &tmh);

    // type-safe access to message details
    int type() const; ///< returns stored type or zero if none
    void address(const struct sockaddr_un& addr); ///< sets [dest.] address
    void getData(int ofType, void *raw, size_t size) const; ///< checks type
    void putData(int aType, const void *raw, size_t size); ///< stores type
	void putFd(int aFd); ///< stores descriptor
	int getFd() const; ///< returns descriptor

    /// raw, type-independent access for I/O
	void prepForReading(); ///< reset and provide all buffers
	char *raw() { return reinterpret_cast<char*>(this); }
	const char *raw() const { return reinterpret_cast<const char*>(this); }
    size_t size() const { return sizeof(*this); } ///< not true message size

private:
	void sync();
	void allocData();
	void allocName();
	void allocControl();

private:
	struct sockaddr_un name; ///< same as .msg_name

	struct iovec ios[1]; ///< same as .msg_iov[]

	struct DataBuffer {
		int type_; ///< Message kind, uses MessageType values
		size_t size; ///< actual raw data size (for sanity checks)
		char raw[250]; ///< buffer with type-specific data
	} data; ///< same as .msg_iov[0].iov_base

	struct CtrlBuffer {
		char raw[CMSG_SPACE(sizeof(int))]; ///< control buffer space for one fd
	} ctrl; ///< same as .msg_control
};

} // namespace Ipc

#endif /* SQUID_IPC_TYPED_MSG_HDR_H */
