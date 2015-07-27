#ifndef SQUID_LOOKUPTABLE_H_
#define SQUID_LOOKUPTABLE_H_

#include "SBuf.h"

#include <map>

/**
 * SBuf -> enum lookup table.
 */
template<class EnumType>
class LookupTable
{
public:
    typedef struct {
        const char *name;
        EnumType id;
    } Record;

    LookupTable(const EnumType theInvalid, const Record data[]) :
        invalidValue(theInvalid)
    {
        for (auto i = 0; data[i].name != nullptr; ++i) {
            lookupTable[SBuf(data[i].name)] = data[i].id;
        }
    }
    EnumType lookup(const SBuf &key) const {
        auto r = lookupTable.find(key);
        if (r == lookupTable.end())
            return invalidValue;
        return r->second;
    }

private:
    typedef std::map<const SBuf, EnumType> lookupTable_t;
    lookupTable_t lookupTable;
    EnumType invalidValue;
};

#endif /* SQUID_LOOKUPTABLE_H_ */
