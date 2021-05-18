/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_INSTANCE_ID_H
#define SQUID_BASE_INSTANCE_ID_H

#include <iosfwd>

/// Represents an InstanceId<C> value independent from its owner class C. These
/// "detached" IDs can be stored by and exchanged among C-unaware users at the
/// price of storing a short scope c-string (that InstanceIds hard-code instead)
/// and, in some cases, using more bits/space than InstanceId<C>::value uses.
class ScopedId
{
public:
    ScopedId(): scope(nullptr), value(0) {}
    explicit ScopedId(const char *s): scope(s), value(0) {}
    // when the values is zero/unknown, use other constructors
    ScopedId(const char *s, uint64_t v): scope(s), value(v) { /* assert(value) */ }

    /// either the prefix() of the InstanceId object that we were detached from
    /// or, for 0 values, some other description (with endless lifetime) or nil
    const char *scope;

    /// either the value of the InstanceId object that we were detached from
    /// or, if our creator did not know the exact value, zero
    uint64_t value;
};

std::ostream &operator <<(std::ostream &os, const ScopedId &id);

typedef unsigned int InstanceIdDefaultValueType;
/** Identifier for class instances
 *   - unique IDs for a large number of concurrent instances, but may wrap;
 *   - useful for debugging and insecure request/response matching;
 *   - sequential IDs within a class except when wrapping;
 *   - always positive IDs.
 * TODO: add creation/destruction debugging?
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

    /// writes a compact text representation of the ID
    std::ostream &print(std::ostream &) const;

    // TODO: Refactor into static Scope().
    /// \returns Class-specific nickname (with endless lifetime)
    const char * prefix() const;

    /// \returns a copy of the ID usable outside our Class context
    ScopedId detach() const { return ScopedId(prefix(), value); }

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

