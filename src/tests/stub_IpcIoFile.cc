/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_DISKIO_IPCIO

#define STUB_API "diskio/IpcIo/IpcIoFile.cc"
#include "tests/STUB.h"

#include "diskio/IpcIo/IpcIoFile.h"
void IpcIoFile::StatQueue(std::ostream &) STUB

#endif /* USE_DISKIO_IPCIO */
