#ifndef _SQUID_COMM_FORWARD_H
#define _SQUID_COMM_FORWARD_H

#include "Array.h"
#include "RefCount.h"

namespace Comm {

class Connection;

typedef RefCount<Comm::Connection> ConnectionPointer;

typedef Vector<Comm::ConnectionPointer> Paths;
typedef Vector<Comm::ConnectionPointer>* PathsPointer;

}; // namespace Comm

#endif /* _SQUID_COMM_FORWARD_H */
