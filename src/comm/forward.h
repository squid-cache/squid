#ifndef _SQUID_COMM_FORWARD_H
#define _SQUID_COMM_FORWARD_H

#include "base/RefCount.h"
#include "base/Vector.h"

namespace Comm
{

class Connection;

typedef RefCount<Comm::Connection> ConnectionPointer;

typedef Vector<Comm::ConnectionPointer> ConnectionList;

bool IsConnOpen(const Comm::ConnectionPointer &conn);

}; // namespace Comm

#endif /* _SQUID_COMM_FORWARD_H */
