/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#ifndef SQUID_SNMPX_VAR_H
#define SQUID_SNMPX_VAR_H

#include "ipc/forward.h"
#include "Range.h"
#include "snmp_vars.h"

namespace Snmp
{

/// variable_list wrapper implement the feature to change
/// the name/value of variable and to pack/unpack message
class Var: public variable_list
{
public:
    Var();
    Var(const Var& var);
    Var& operator = (const Var& var);
    ~Var();

    Var& operator += (const Var& var);
    Var& operator /= (int num);
    bool operator < (const Var& var) const;
    bool operator > (const Var& var) const;

    void pack(Ipc::TypedMsgHdr& msg) const; ///< prepare for sendmsg()
    void unpack(const Ipc::TypedMsgHdr& msg); ///< restore struct from the message

    Range<const oid*> getName() const; ///< returns variable name
    void setName(const Range<const oid*>& aName); ///< set new variable name
    void clearName(); ///< clear variable name

    bool isNull() const;

    int asInt() const; ///< returns variable value as integer
    unsigned int asGauge() const; ///< returns variable value as unsigned int
    int asCounter() const; ///< returns variable value as Counter32
    long long int asCounter64() const; ///< returns variable value as Counter64
    unsigned int asTimeTicks() const; ///< returns variable value as time ticks
    Range<const oid*> asObject() const; ///< returns variable value as object oid
    Range<const u_char*> asString() const; ///< returns variable value as chars string

    void setInt(int value); ///< assign int value to variable
    void setCounter(int value); ///< assign Counter32 value to variable
    void setGauge(unsigned int value); ///< assign unsigned int value to variable
    void setString(const Range<const u_char*>& string); ///< assign string to variable
    void setObject(const Range<const oid*>& object); ///< assign object oid to variable
    void setTimeTicks(unsigned int ticks); ///<assign unsigned int (time) value to variable
    void setCounter64(long long int counter); ///< assign Counter64 value to variable

    void copyValue(const Var& var); ///< copy variable from another one
    void clearValue(); ///< clear .val member
    void clear();  ///< clear all internal members

private:
    void init(); ///< initialize members
    void assign(const Var& var); ///< perform full assignment
    void setValue(const void* value, int length, int aType); ///< set new variable value
};

} // namespace Snmp

#endif /* SQUID_SNMPX_VAR_H */

