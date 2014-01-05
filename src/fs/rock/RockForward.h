#ifndef SQUID_FS_ROCK_FORWARD_H
#define SQUID_FS_ROCK_FORWARD_H

namespace Ipc
{

class StoreMapAnchor;
class StoreMapSlice;

namespace Mem
{
class PageId;
}

}

namespace Rock
{

class SwapDir;

/// db cell number, starting with cell 0 (always occupied by the db header)
typedef sfileno SlotId;

class Rebuild;

class IoState;

class DbCellHeader;

}

#endif /* SQUID_FS_ROCK_FORWARD_H */
