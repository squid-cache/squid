#include "squid.h"
#include "ipc/Forwarder.h"

//Avoid linker errors about Ipc::Forwarder
void foo_stub_ipc_forwarder()
{
    Ipc::Forwarder foo(NULL,1.0);
}
