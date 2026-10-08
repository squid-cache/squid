/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#include "squid.h"
#include "base/TextException.h"
#include "debug/Stream.h"
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
    memset(static_cast<variable_list *>(this), 0, sizeof(variable_list));
}

Snmp::Var&
Snmp::Var::operator += (const Var& var)
{
    switch (type) {
    case ASN_INTEGER:
        setInt(asInt() + var.asInt());
        break;
    case ASN_GAUGE:
        setGauge(asGauge() + var.asGauge());
        break;
    case ASN_COUNTER:
        setCounter(asCounter() + var.asCounter());
        break;
    case ASN_COUNTER64:
        setCounter64(asCounter64() + var.asCounter64());
        break;
    case ASN_TIMETICKS:
        setTimeTicks(asTimeTicks() + var.asTimeTicks());
        break;
    default:
        debugs(49, DBG_CRITICAL, "ERROR: Unsupported type: " << type);
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
    case ASN_INTEGER:
        setInt(asInt() / num);
        break;
    case ASN_GAUGE:
        setGauge(asGauge() / num);
        break;
    case ASN_COUNTER:
        setCounter(asCounter() / num);
        break;
    case ASN_COUNTER64:
        setCounter64(asCounter64() / num);
        break;
    case ASN_TIMETICKS:
        setTimeTicks(asTimeTicks() / num);
        break;
    default:
        debugs(49, DBG_CRITICAL, "ERROR: Unsupported type: " << type);
        throw TexcHere("Unsupported type");
        break;
    }
    return *this;
}

bool
Snmp::Var::operator < (const Var& var) const
{
    switch (type) {
    case ASN_INTEGER:
        return asInt() < var.asInt();
    case ASN_GAUGE:
        return asGauge() < var.asGauge();
    case ASN_COUNTER:
        return asCounter() < var.asCounter();
    case ASN_COUNTER64:
        return asCounter64() < var.asCounter64();
    case ASN_TIMETICKS:
        return asTimeTicks() < var.asTimeTicks();
    default:
        debugs(49, DBG_CRITICAL, "ERROR: Unsupported type: " << type);
        throw TexcHere("Unsupported type");
        break;
    }
    return false; // unreachable
}

bool
Snmp::Var::operator > (const Var& var) const
{
    switch (type) {
    case ASN_INTEGER:
        return asInt() > var.asInt();
    case ASN_GAUGE:
        return asGauge() > var.asGauge();
    case ASN_COUNTER:
        return asCounter() > var.asCounter();
    case ASN_COUNTER64:
        return asCounter64() > var.asCounter64();
    case ASN_TIMETICKS:
        return asTimeTicks() > var.asTimeTicks();
    default:
        debugs(49, DBG_CRITICAL, "ERROR: Unsupported type: " << type);
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
    xfree(name);
    name = nullptr;
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
    xfree(val.string);
    val.string = nullptr;
    val_len = 0;
    type = 0;
}

bool
Snmp::Var::isNull() const
{
    return type == ASN_NULL;
}

int
Snmp::Var::asInt() const
{
    Must(type == ASN_INTEGER);
    Must(val.integer != nullptr && val_len == sizeof(int));
    return *val.integer;
}

unsigned int
Snmp::Var::asGauge() const
{
    Must(type == ASN_GAUGE);
    Must(val.integer != nullptr && val_len == 4);
    return *reinterpret_cast<unsigned int*>(val.integer);
}

int
Snmp::Var::asCounter() const
{
    Must(type == ASN_COUNTER);
    Must(val.integer != nullptr && val_len == 4);
    return *reinterpret_cast<int*>(val.integer);
}

long long int
Snmp::Var::asCounter64() const
{
    Must(type == ASN_COUNTER64);
    Must(val.integer != nullptr && val_len == 8);
    return *reinterpret_cast<long long int*>(val.integer);
}

unsigned int
Snmp::Var::asTimeTicks() const
{
    Must(type == ASN_TIMETICKS);
    Must(val.integer != nullptr && val_len == sizeof(unsigned int));
    return *reinterpret_cast<unsigned int*>(val.integer);
}

Range<const oid*>
Snmp::Var::asObject() const
{
    Must(type == ASN_OBJECT_ID);
    Must(val_len % sizeof(oid) == 0);
    int length = val_len / sizeof(oid);
    Must(val.objid != nullptr && length > 0);
    return Range<const oid*>(val.objid, val.objid + length);
}

Range<const u_char*>
Snmp::Var::asString() const
{
    Must(type == ASN_OCTET_STR);
    Must(val.string != nullptr && val_len > 0);
    return Range<const u_char*>(val.string, val.string + val_len);
}

void
Snmp::Var::setInt(int value)
{
    setValue(&value, sizeof(value), ASN_INTEGER);
}

void
Snmp::Var::setCounter(int value)
{
    setValue(&value, sizeof(value), ASN_COUNTER);
}

void
Snmp::Var::setGauge(unsigned int value)
{
    setValue(&value, sizeof(value), ASN_GAUGE);
}

void
Snmp::Var::setString(const Range<const u_char*>& string)
{
    setValue(string.start, string.size(), ASN_OCTET_STR);
}

void
Snmp::Var::setObject(const Range<const oid*>& object)
{
    setValue(object.start, object.size() * sizeof(oid), ASN_OBJECT_ID);
}

void
Snmp::Var::setCounter64(long long int counter)
{
    setValue(&counter, sizeof(counter), ASN_COUNTER64);
}

void
Snmp::Var::setTimeTicks(unsigned int ticks)
{
    setValue(&ticks, sizeof(ticks), ASN_TIMETICKS);
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
    if (value != nullptr) {
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
        Must(name != nullptr);
        msg.putFixed(name, name_length * sizeof(oid));
    }
    msg.putPod(type);
    msg.putPod(val_len);
    if (val_len > 0) {
        Must(val.string != nullptr);
        msg.putFixed(val.string, val_len);
    }
}

void
Snmp::Var::unpack(const Ipc::TypedMsgHdr& msg)
{
    clearName();
    clearValue();
    name_length = msg.getInt();
    if (name_length > 0) {
        name = static_cast<oid*>(xmalloc(name_length * sizeof(oid)));
        msg.getFixed(name, name_length * sizeof(oid));
    }
    msg.getPod(type);
    val_len = msg.getInt();
    if (val_len > 0) {
        val.string = static_cast<u_char*>(xmalloc(val_len));
        msg.getFixed(val.string, val_len);
    }
}

