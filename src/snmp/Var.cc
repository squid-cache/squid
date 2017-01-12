/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#include "squid.h"
#include "base/TextException.h"
#include "Debug.h"
#include "ipc/TypedMsgHdr.h"
#include "snmp/Var.h"
#include "tools.h"

#include <algorithm>

Snmp::Var::Var()
{
    init();
}

Snmp::Var::Var(const Var& var)
{
    init();
    assign(var);
}

Snmp::Var::~Var()
{
    clear();
}

Snmp::Var&
Snmp::Var::operator = (const Var& var)
{
    clear();
    assign(var);
    return *this;
}

void
Snmp::Var::init()
{
    memset(this, 0, sizeof(*this));
}

Snmp::Var&
Snmp::Var::operator += (const Var& var)
{
    switch (type) {
    case SMI_INTEGER:
        setInt(asInt() + var.asInt());
        break;
    case SMI_GAUGE32:
        setGauge(asGauge() + var.asGauge());
        break;
    case SMI_COUNTER32:
        setCounter(asCounter() + var.asCounter());
        break;
    case SMI_COUNTER64:
        setCounter64(asCounter64() + var.asCounter64());
        break;
    case SMI_TIMETICKS:
        setTimeTicks(asTimeTicks() + var.asTimeTicks());
        break;
    default:
        debugs(49, DBG_CRITICAL, HERE << "Unsupported type: " << type);
        throw TexcHere("Unsupported type");
        break;
    }
    return *this;
}

Snmp::Var&
Snmp::Var::operator /= (int num)
{
    Must(num != 0);
    switch (type) {
    case SMI_INTEGER:
        setInt(asInt() / num);
        break;
    case SMI_GAUGE32:
        setGauge(asGauge() / num);
        break;
    case SMI_COUNTER32:
        setCounter(asCounter() / num);
        break;
    case SMI_COUNTER64:
        setCounter64(asCounter64() / num);
        break;
    case SMI_TIMETICKS:
        setTimeTicks(asTimeTicks() / num);
        break;
    default:
        debugs(49, DBG_CRITICAL, HERE << "Unsupported type: " << type);
        throw TexcHere("Unsupported type");
        break;
    }
    return *this;
}

bool
Snmp::Var::operator < (const Var& var) const
{
    switch (type) {
    case SMI_INTEGER:
        return asInt() < var.asInt();
    case SMI_GAUGE32:
        return asGauge() < var.asGauge();
    case SMI_COUNTER32:
        return asCounter() < var.asCounter();
    case SMI_COUNTER64:
        return asCounter64() < var.asCounter64();
    case SMI_TIMETICKS:
        return asTimeTicks() < var.asTimeTicks();
    default:
        debugs(49, DBG_CRITICAL, HERE << "Unsupported type: " << type);
        throw TexcHere("Unsupported type");
        break;
    }
    return false; // unreachable
}

bool
Snmp::Var::operator > (const Var& var) const
{
    switch (type) {
    case SMI_INTEGER:
        return asInt() > var.asInt();
    case SMI_GAUGE32:
        return asGauge() > var.asGauge();
    case SMI_COUNTER32:
        return asCounter() > var.asCounter();
    case SMI_COUNTER64:
        return asCounter64() > var.asCounter64();
    case SMI_TIMETICKS:
        return asTimeTicks() > var.asTimeTicks();
    default:
        debugs(49, DBG_CRITICAL, HERE << "Unsupported type: " << type);
        throw TexcHere("Unsupported type");
        break;
    }
    return false; // unreachable
}

void
Snmp::Var::assign(const Var& var)
{
    setName(var.getName());
    copyValue(var);
}

void
Snmp::Var::clearName()
{
    if (name != NULL) {
        xfree(name);
        name = NULL;
    }
    name_length = 0;
}

Range<const oid*>
Snmp::Var::getName() const
{
    return Range<const oid*>(name, name + name_length);
}

void
Snmp::Var::setName(const Range<const oid*>& aName)
{
    clearName();
    if (aName.start != NULL && aName.size() != 0) {
        name_length = aName.size();
        name = static_cast<oid*>(xmalloc(name_length * sizeof(oid)));
        std::copy(aName.start, aName.end, name);
    }
}

void
Snmp::Var::clearValue()
{
    if (val.string != NULL) {
        xfree(val.string);
        val.string = NULL;
    }
    val_len = 0;
    type = 0;
}

bool
Snmp::Var::isNull() const
{
    return type == SMI_NULLOBJ;
}

int
Snmp::Var::asInt() const
{
    Must(type == SMI_INTEGER);
    Must(val.integer != NULL && val_len == sizeof(int));
    return *val.integer;
}

unsigned int
Snmp::Var::asGauge() const
{
    Must(type == SMI_GAUGE32);
    Must(val.integer != NULL && val_len == 4);
    return *reinterpret_cast<unsigned int*>(val.integer);
}

int
Snmp::Var::asCounter() const
{
    Must(type == SMI_COUNTER32);
    Must(val.integer != NULL && val_len == 4);
    return *reinterpret_cast<int*>(val.integer);
}

long long int
Snmp::Var::asCounter64() const
{
    Must(type == SMI_COUNTER64);
    Must(val.integer != NULL && val_len == 8);
    return *reinterpret_cast<long long int*>(val.integer);
}

unsigned int
Snmp::Var::asTimeTicks() const
{
    Must(type == SMI_TIMETICKS);
    Must(val.integer != NULL && val_len == sizeof(unsigned int));
    return *reinterpret_cast<unsigned int*>(val.integer);
}

Range<const oid*>
Snmp::Var::asObject() const
{
    Must(type == SMI_OBJID);
    Must(val_len % sizeof(oid) == 0);
    int length = val_len / sizeof(oid);
    Must(val.objid != NULL && length > 0);
    return Range<const oid*>(val.objid, val.objid + length);
}

Range<const u_char*>
Snmp::Var::asString() const
{
    Must(type == SMI_STRING);
    Must(val.string != NULL && val_len > 0);
    return Range<const u_char*>(val.string, val.string + val_len);
}

void
Snmp::Var::setInt(int value)
{
    setValue(&value, sizeof(value), SMI_INTEGER);
}

void
Snmp::Var::setCounter(int value)
{
    setValue(&value, sizeof(value), SMI_COUNTER32);
}

void
Snmp::Var::setGauge(unsigned int value)
{
    setValue(&value, sizeof(value), SMI_GAUGE32);
}

void
Snmp::Var::setString(const Range<const u_char*>& string)
{
    setValue(string.start, string.size(), SMI_STRING);
}

void
Snmp::Var::setObject(const Range<const oid*>& object)
{
    setValue(object.start, object.size() * sizeof(oid), SMI_OBJID);
}

void
Snmp::Var::setCounter64(long long int counter)
{
    setValue(&counter, sizeof(counter), SMI_COUNTER64);
}

void
Snmp::Var::setTimeTicks(unsigned int ticks)
{
    setValue(&ticks, sizeof(ticks), SMI_TIMETICKS);
}

void
Snmp::Var::copyValue(const Var& var)
{
    setValue(var.val.string, var.val_len, var.type);
}

void
Snmp::Var::setValue(const void* value, int length, int aType)
{
    clearValue();
    if (value != NULL) {
        Must(length > 0 && aType > 0);
        val.string = static_cast<u_char*>(xmalloc(length));
        memcpy(val.string, value, length);
    }
    val_len = length;
    type = aType;
}

void
Snmp::Var::clear()
{
    clearName();
    clearValue();
    init();
}

void
Snmp::Var::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.putInt(name_length);
    if (name_length > 0) {
        Must(name != NULL);
        msg.putFixed(name, name_length * sizeof(oid));
    }
    msg.putPod(type);
    msg.putPod(val_len);
    if (val_len > 0) {
        Must(val.string != NULL);
        msg.putFixed(val.string, val_len);
    }
}

void
Snmp::Var::unpack(const Ipc::TypedMsgHdr& msg)
{
    clearName();
    clearValue();
    name_length = msg.getInt();
    Must(name_length >= 0);
    if (name_length > 0) {
        name = static_cast<oid*>(xmalloc(name_length * sizeof(oid)));
        msg.getFixed(name, name_length * sizeof(oid));
    }
    msg.getPod(type);
    val_len = msg.getInt();
    Must(val_len >= 0);
    if (val_len > 0) {
        val.string = static_cast<u_char*>(xmalloc(val_len));
        msg.getFixed(val.string, val_len);
    }
}

