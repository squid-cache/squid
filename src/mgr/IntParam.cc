/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/IntParam.h"

Mgr::IntParam::IntParam():
        QueryParam(QueryParam::ptInt), array()
{
}

Mgr::IntParam::IntParam(const std::vector<int>& anArray):
        QueryParam(QueryParam::ptInt), array(anArray)
{
}

void
Mgr::IntParam::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.putPod(type);
    msg.putInt(array.size());
    typedef std::vector<int>::const_iterator Iterator;
    for (Iterator iter = array.begin(); iter != array.end(); ++iter)
        msg.putInt(*iter);
}

void
Mgr::IntParam::unpackValue(const Ipc::TypedMsgHdr& msg)
{
    array.clear();
    int count = msg.getInt();
    Must(count >= 0);
    for ( ; count > 0; --count)
        array.push_back(msg.getInt());
}

const std::vector<int>&
Mgr::IntParam::value() const
{
    return array;
}
