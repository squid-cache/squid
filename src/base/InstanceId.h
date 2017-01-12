/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_INSTANCE_ID_H
#define SQUID_BASE_INSTANCE_ID_H

#include <iosfwd>

/** Identifier for class instances
 *   - unique IDs for a large number of concurrent instances, but may wrap;
 *   - useful for debugging and insecure request/response matching;
 *   - sequential IDs within a class except when wrapping;
 *   - always positive IDs.
 *  \todo: add storage type parameter to support configurable Value types?
 *  \todo: add creation/destruction debugging?
 */
template <class Class>
class InstanceId
{
public:
    typedef unsigned int Value; ///< id storage type; \todo: parameterize?

    InstanceId(): value(0) {change();}

    operator Value() const { return value; }
    bool operator ==(const InstanceId &o) const { return value == o.value; }
    bool operator !=(const InstanceId &o) const { return !(*this == o); }
    void change();

    /// prints class-pecific prefix followed by ID value; \todo: use HEX for value printing?
    std::ostream &print(std::ostream &os) const;

    /// returns the class-pecific prefix
    const char * const prefix() const;

public:
    Value value; ///< instance identifier

private:
    InstanceId(const InstanceId& right); ///< not implemented; IDs are unique
    InstanceId& operator=(const InstanceId &right); ///< not implemented
};

/// convenience macro to instantiate Class-specific stuff in .cc files
#define InstanceIdDefinitions(Class, pfx) \
    template<> const char * const \
    InstanceId<Class>::prefix() const { \
        return pfx; \
    } \
    template<> std::ostream & \
    InstanceId<Class>::print(std::ostream &os) const { \
        return os << pfx << value; \
    } \
    template<> void \
    InstanceId<Class>::change() { \
        static InstanceId<Class>::Value Last = 0; \
        value = ++Last ? Last : ++Last; \
    }

/// print the id
template <class Class>
inline
std::ostream &operator <<(std::ostream &os, const InstanceId<Class> &id)
{
    return id.print(os);
}

#endif /* SQUID_BASE_INSTANCE_ID_H */

