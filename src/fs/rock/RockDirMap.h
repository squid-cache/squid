#ifndef SQUID_FS_ROCK_DIR_MAP_H
#define SQUID_FS_ROCK_DIR_MAP_H

namespace Rock {

/// \ingroup Rock
/// map of used db slots indexed by sfileno
class DirMap
{
public:
    DirMap(const int aLimit = 0);
    DirMap(const DirMap &map);
    ~DirMap();

    DirMap &operator =(const DirMap &map);
    void resize(const int newLimit); ///< forgets higher slots or appends zeros

    bool full() const; ///< there are no empty slots left
    bool has(int n) const; ///< whether slot n is occupied
    bool valid(int n) const; ///< whether n is a valid slot coordinate
    int entryCount() const; ///< number of used slots
    int entryLimit() const; ///< maximum number of slots that can be used

    void use(int n); ///< mark slot n as used
    void clear(int n); ///< mark slot n as unused
    int useNext(); ///< finds and uses an empty slot, returning its coordinate

    static int AbsoluteEntryLimit(); ///< maximum entryLimit() possible

private:
    /// unreliable next empty slot suggestion #1 (clear based)
    mutable int hintPast;
    ///< unreliable next empty slot suggestion #2 (scan based)
    mutable int hintNext;

    int limit; ///< maximum number of map slots
    int count; ///< current number of map slots

    typedef uint8_t Slot;
    Slot *slots; ///< slots storage

    int ramSize() const;
    void allocate();
    void deallocate();
    void copyFrom(const DirMap &map);
    int findNext() const;
};

} // namespace Rock

// We do not reuse struct _fileMap because we cannot control its size,
// resulting in sfilenos that are pointing beyond the database.

#endif /* SQUID_FS_ROCK_DIR_MAP_H */
