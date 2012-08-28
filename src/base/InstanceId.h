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

    InstanceId(): value(++Last ? Last : ++Last) {}

    operator Value() const { return value; }
    bool operator ==(const InstanceId &o) const { return value == o.value; }
    bool operator !=(const InstanceId &o) const { return !(*this == o); }
    void change() {value = ++Last ? Last : ++Last;}

    /// prints Prefix followed by ID value; \todo: use HEX for value printing?
    std::ostream &print(std::ostream &os) const;

public:
    static const char *Prefix; ///< Class shorthand string for debugging
    Value value; ///< instance identifier

private:
    InstanceId(const InstanceId& right); ///< not implemented; IDs are unique
    InstanceId& operator=(const InstanceId &right); ///< not implemented

private:
    static Value Last; ///< the last used ID value
};

/// convenience macro to instantiate Class-specific stuff in .cc files
#define InstanceIdDefinitions(Class, prefix) \
    template<> const char *InstanceId<Class>::Prefix = prefix; \
    template<> InstanceId<Class>::Value InstanceId<Class>::Last = 0; \
    template<> std::ostream & \
    InstanceId<Class>::print(std::ostream &os) const { \
        return os << Prefix << value; \
    }

/// print the id
template <class Class>
inline
std::ostream &operator <<(std::ostream &os, const InstanceId<Class> &id)
{
    return id.print(os);
}

#endif /* SQUID_BASE_INSTANCE_ID_H */
