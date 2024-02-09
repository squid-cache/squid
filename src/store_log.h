/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Logging Functions */

#ifndef SQUID_SRC_STORE_LOG_H
#define SQUID_SRC_STORE_LOG_H

class StoreEntry;

void storeLog(int tag, const StoreEntry * e);
void storeLogRotate(void);
void storeLogClose(void);
void storeLogOpen(void);

#endif /* SQUID_SRC_STORE_LOG_H */

