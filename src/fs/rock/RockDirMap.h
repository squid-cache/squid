#ifndef SQUID_FS_ROCK_DIR_MAP_H
#define SQUID_FS_ROCK_DIR_MAP_H

namespace Rock {

/// \ingroup Rock
/// bitmap of used db slots indexed by sfileno
class DirMap
{
public:
    // the map may adjust the limit down a little; see roundLimit()
    DirMap(const int roughLimit = 0);
    DirMap(const DirMap &map);
    ~DirMap();

    DirMap &operator =(const DirMap &map);
    void resize(const int newLimit); ///< forgets higher bits or appends zeros

    bool full() const; ///< there are no empty slots left
    bool has(int n) const; ///< whether slot n is occupied
    bool valid(int n) const; ///< whether n is a valid slot coordinate
    int entryCount() const; ///< number of bits turned on
    int entryLimit() const; ///< maximum number of bits that can be turned on

    void use(int n); ///< mark slot n as used
    void clear(int n); ///< mark slot n as unused
    int useNext(); ///< finds and uses an empty slot, returning its coordinate

    static int AbsoluteEntryLimit(); ///< maximum entryLimit() possible

private:
    /// unreliable next empty slot suggestion #1 (clear based)
    mutable int hintPast;
    ///< unreliable next empty slot suggestion #2 (scan based)
    mutable int hintNext;

    int bitLimit; ///< maximum number of map entries
    int bitCount; ///< current number of map entries

    unsigned long *words; ///< low level storage
    int wordCount; ///< number of words allocated

    int roundLimit(const int roughLimit) const;
    void syncWordCount();
    int ramSize() const;
    void allocate();
    void deallocate();
    void copyFrom(const DirMap &map);
    int findNext() const;
};

} // namespace Rock

// We do not reuse struct _fileMap because we cannot control its size,
// resulting in sfilenos that are pointing beyond the database.

// TODO: Consider using std::bitset. Is it really slower for findNext()?


#endif /* SQUID_FS_ROCK_DIR_MAP_H */
