#include "squid.h"
#include "fde.h"

#define STUB_API "fd.cc"
#include "tests/STUB.h"

fde *fde::Table = NULL;

int fdNFree(void) STUB_RETVAL(-1)
void fd_open(int fd, unsigned int type, const char *desc) STUB
void fd_close(int fd) STUB
void fd_bytes(int fd, int len, unsigned int type) STUB
void fd_note(int fd, const char *s) STUB
void fdAdjustReserved() STUB
