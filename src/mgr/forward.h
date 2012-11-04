/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#ifndef SQUID_MGR_FORWARD_H
#define SQUID_MGR_FORWARD_H

#include "base/RefCount.h"

namespace Mgr
{

class Action;
class ActionCreator;
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

#endif /* SQUID_MGR_FORWARD_H */
