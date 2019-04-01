/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_FORWARD_H
#define SQUID_MGR_FORWARD_H

#include "base/RefCount.h"

/// Cache Manager API
namespace Mgr
{

class Action;
class ActionCreator;
class ActionPasswordList;
class ActionProfile;
class ActionWriter;
class Command;
class Request;
class Response;
class QueryParam;
class QueryParams;

typedef RefCount<Action> ActionPointer;
typedef RefCount<ActionProfile> ActionProfilePointer;
typedef RefCount<ActionCreator> ActionCreatorPointer;
typedef RefCount<Command> CommandPointer;

typedef ActionPointer (ClassActionCreationHandler)(const CommandPointer &cmd);

} // namespace Mgr

class StoreEntry;
/**
 * Handler for "dumping" out a cachemgr report to a StoreEntry
 */
typedef void OBJH(StoreEntry *);

#endif /* SQUID_MGR_FORWARD_H */

