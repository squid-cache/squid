/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 08    Swap File Bitmap */

#ifndef FILEMAP_H_
#define FILEMAP_H_

#include "typedefs.h"

/** A bitmap used for managing UFS StoreEntry "file numbers".
 *
 * Nth bit represents whether file number N is used.
 * The map automatically grows to hold up to 2^24 bits.
 * New bit is "off" or zero by default, representing unused fileno.
 * TODO: consider using std::bitset instead.
 */
class FileMap
{
public:
    FileMap();
    ~FileMap();

    /** Set the num-th bit in the FileMap
     *
     * \warning FileMap's backing storage will be extended as needed to
     * hold the representation, but  if the bit is already set
     * it will break the file number accounting, so the caller must
     * ensure that setBit is only called if the bit is not already set,
     * by using testBit on it before.
     */
    bool setBit(sfileno num);

    /// Test whether the num-th bit in the FileMap is set
    bool testBit(sfileno num) const;

    /** Clear the num-th bit in the FileMap
     *
     * \warning that clearBit doesn't do any bounds checking, nor it
     * checks that the bit is set before clearing. The caller will have
     * to ensure that both are true using testBit before clearing.
     */
    void clearBit(sfileno num);

    /** locate an unused slot in the FileMap, possibly at or after position suggestion
     *
     * Obtain the location of an unused slot in the FileMap,
     * growing it if needed.
     * The suggestion is only an advice; there is no guarantee
     * that it will be followed.
     */
    sfileno allocate(sfileno suggestion);

    /// return the max number of slots in the FileMap
    int capacity() const {return capacity_;}

    /// return the number of used slots in the FileMap
    int numFilesInMap() const {return usedSlots_;}
private:
    /// grow the FileMap (size is doubled each time, up to 2^24 bits)
    void grow();
    FileMap(const FileMap &); //no copying
    FileMap& operator=(const FileMap &); //no assignments

    /// max number of files which can be tracked in the current store
    sfileno capacity_;
    /// used slots in the map
    unsigned int usedSlots_;
    /// number of "long ints" making up the filemap
    unsigned int nwords;
    unsigned long *bitmap;
};

#endif /* FILEMAP_H_ */

