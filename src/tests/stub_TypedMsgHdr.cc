#include "config.h"
#include "fatal.h"
#include "ipc/TypedMsgHdr.h"

Ipc::TypedMsgHdr::TypedMsgHdr()
{
    fatal("Not implemented");
}

void
Ipc::TypedMsgHdr::getFixed(void *raw, size_t size) const
{
    fatal("Not implemented");
}

void
Ipc::TypedMsgHdr::putFixed(const void *raw, size_t size)
{
    fatal("Not implemented");
}

void
Ipc::TypedMsgHdr::getString(String &size) const
{
    fatal("Not implemented");
}

void
Ipc::TypedMsgHdr::putString(const String & size)
{
    fatal("Not implemented");
}

void
Ipc::TypedMsgHdr::checkType(int destType) const
{
    fatal("Not implemented");
}

void
Ipc::TypedMsgHdr::setType(int aType)
{
    fatal("Not implemented");
}
