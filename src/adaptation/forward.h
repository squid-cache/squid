/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ADAPTATION__FORWARD_H
#define SQUID_ADAPTATION__FORWARD_H

// forward-declarations for commonly used adaptation classes

template <class C>
class RefCount;

// For various collections such as AllServices
// TODO: use std::hash_map<> instead
template <class Item>
class Vector;

namespace Adaptation
{

class Service;
class ServiceConfig;
class DynamicGroupCfg;
class Class;
class Initiate;
class Initiator;
class AccessCheck;
class AccessRule;
class ServiceGroup;
class ServicePlan;
class ServiceFilter;
class Message;
class Answer;

typedef RefCount<Service> ServicePointer;
typedef RefCount<ServiceConfig> ServiceConfigPointer;
typedef RefCount<ServiceGroup> ServiceGroupPointer;

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__FORWARD_H */

