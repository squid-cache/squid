/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Logging Functions */

#ifndef SQUID_STORE_LOG_H_
#define SQUID_STORE_LOG_H_

class StoreEntry;

void storeLog(int tag, const StoreEntry * e);
void storeLogRotate(void);
void storeLogClose(void);
void storeLogOpen(void);

#endif /* SQUID_STORE_LOG_H_ */

