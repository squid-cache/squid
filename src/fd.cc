#include "squid.h"

static void fdUpdateBiggest _PARAMS((int fd, unsigned int status));

static void
fdUpdateBiggest(int fd, unsigned int status)
{
    if (fd < Biggest_FD)
	return;
    assert(fd < Squid_MaxFD);
    if (fd > Biggest_FD) {
	assert(status == FD_OPEN);
	Biggest_FD = fd;
	return;
    }
    /* if we are here, then fd == Biggest_FD */
    assert(status == FD_CLOSE);
    while (fd_table[Biggest_FD].open != FD_OPEN)
	Biggest_FD--;
}

void
fd_close(int fd)
{
    fde *F = &fd_table[fd];
    if (F->type == FD_FILE) {
	assert(F->read_handler == NULL);
	assert(F->write_handler == NULL);
    }
    fdUpdateBiggest(fd, F->open = FD_CLOSE);
    memset(F, '\0', sizeof(fde));
    F->timeout = 0;
}

void
fd_open(int fd, unsigned int type, const char *desc)
{
    fde *F = &fd_table[fd];
    assert(F->open == 0);
    F->type = type;
    fdUpdateBiggest(fd, F->open = FD_OPEN);
    if (desc)
	xstrncpy(F->desc, desc, FD_DESC_SZ);
}

void
fd_note(int fd, const char *s)
{
    fde *F = &fd_table[fd];
    xstrncpy(F->desc, s, FD_DESC_SZ);
}

void
fd_bytes(int fd, int len, unsigned int type)
{
    fde *F = &fd_table[fd];
    if (len < 0)
	return;
    assert(type == FD_READ || type == FD_WRITE);
    if (type == FD_READ)
	F->bytes_read += len;
    else
	F->bytes_written += len;
}

void
fdFreeMemory(void)
{
    safe_free(fd_table);
}

void
fdDumpOpen(void)
{
    int i;
    fde *F;
    for (i = 0; i < Squid_MaxFD; i++) {
	F = &fd_table[i];
	if (!F->open)
	    continue;
	if (i == fileno(debug_log))
	    continue;
	debug(5, 1) ("Open FD %4d %s\n", i, F->desc);
    }
}
