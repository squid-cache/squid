#ifndef SQUID_ADAPTATION__FORWARD_H
#define SQUID_ADAPTATION__FORWARD_H

// forward-declarations for commonly used adaptation classes

template <class C>
class RefCount;

// For various collections such as AllServices
// TODO: use std::hash_map<> instead
template <class Item>
class Vector;

namespace Adaptation {

class Service;
class ServiceConfig;
class Class;
class Initiate;
class Initiator;
class AccessCheck;
class AccessRule;
class ServiceGroup;
class Message;

typedef RefCount<Service> ServicePointer;

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__FORWARD_H */
