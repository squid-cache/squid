/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_INSTANCE_ID_H
#define SQUID_BASE_INSTANCE_ID_H

#include <iosfwd>

typedef unsigned int InstanceIdDefaultValueType;
/** Identifier for class instances
 *   - unique IDs for a large number of concurrent instances, but may wrap;
 *   - useful for debugging and insecure request/response matching;
 *   - sequential IDs within a class except when wrapping;
 *   - always positive IDs.
 *  \todo: add creation/destruction debugging?
 */
template <class Class, class ValueType = InstanceIdDefaultValueType>
class InstanceId
{
public:
    typedef ValueType Value; ///< id storage type

    InstanceId() {change();}

    operator Value() const { return value; }
    bool operator ==(const InstanceId &o) const { return value == o.value; }
    bool operator !=(const InstanceId &o) const { return !(*this == o); }
    void change();

    /// prints class-pecific prefix followed by ID value; \todo: use HEX for value printing?
    std::ostream &print(std::ostream &) const;

    /// returns the class-pecific prefix
    const char * prefix() const;

public:
    Value value = Value(); ///< instance identifier

private:
    InstanceId(const InstanceId &); ///< not implemented; IDs are unique
    InstanceId& operator=(const InstanceId &); ///< not implemented
};

/// An InstanceIdDefinitions() helper. Avoid direct use.
#define InstanceIdDefinitions3(Class, pfx, ValueType, ...) \
    template<> const char * \
    InstanceId<Class, ValueType>::prefix() const { \
        return pfx; \
    } \
    template<> std::ostream & \
    InstanceId<Class, ValueType>::print(std::ostream &os) const { \
        return os << pfx << value; \
    } \
    template<> void \
    InstanceId<Class, ValueType>::change() { \
        static auto Last = Value(); \
        value = ++Last ? Last : ++Last; \
    }

/// convenience macro to instantiate Class-specific stuff in .cc files
#define InstanceIdDefinitions(...) InstanceIdDefinitions3(__VA_ARGS__, InstanceIdDefaultValueType)

/// print the id
template <class Class, class ValueType>
inline
std::ostream &operator <<(std::ostream &os, const InstanceId<Class, ValueType> &id)
{
    return id.print(os);
}

#endif /* SQUID_BASE_INSTANCE_ID_H */

