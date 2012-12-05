/*
 * DEBUG: section 79    Disk IO Routines
 */

#include "squid.h"
#include "fs/rock/RockDbCell.h"
#include "ipc/StoreMap.h"
#include "tools.h"

Rock::DbCellHeader::DbCellHeader(): firstSlot(0), nextSlot(0), version(0),
        payloadSize(0) {
    memset(&key, 0, sizeof(key));
}

bool
Rock::DbCellHeader::sane() const {
    return firstSlot > 0;
}
