/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/ActionParams.h"

Mgr::ActionParams::ActionParams(): httpMethod(METHOD_NONE)
{
}

Mgr::ActionParams::ActionParams(const Ipc::TypedMsgHdr &msg)
{
    msg.getString(httpUri);

    const int m = msg.getInt();
    Must(METHOD_NONE <= m && m < METHOD_ENUM_END);
    httpMethod = static_cast<_method_t>(m);

    msg.getPod(httpFlags);
    msg.getString(httpOrigin);

    msg.getString(actionName);
    msg.getString(userName);
    msg.getString(password);
    queryParams.unpack(msg);
}

void
Mgr::ActionParams::pack(Ipc::TypedMsgHdr &msg) const
{
    msg.putString(httpUri);
    msg.putInt(httpMethod);
    msg.putPod(httpFlags);
    msg.putString(httpOrigin);

    msg.putString(actionName);
    msg.putString(userName);
    msg.putString(password);
    queryParams.pack(msg);
}
