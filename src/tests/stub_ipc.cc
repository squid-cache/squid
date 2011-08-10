#include "config.h"
// because ipcCreate is defined in protos.h still
#include "protos.h"

pid_t
ipcCreate(int type, const char *prog, const char *const args[], const char *name, Ip::Address &local_addr, int *rfd, int *wfd, void **hIpc)
{
    fatal("ipc.cc required.");
    return -1;
}
