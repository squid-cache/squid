#ifndef SQUID_ADAPTATION__FORWARD_H
#define SQUID_ADAPTATION__FORWARD_H

// forward-declarations for commonly used adaptation classes

template <class C>
class RefCount;

namespace Adaptation {

class Service;
class ServiceConfig;
class Class;
class Initiate;
class Initiator;
class AccessCheck;

typedef RefCount<Service> ServicePointer;

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__FORWARD_H */
