/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/IntParam.h"
#include "mgr/QueryParams.h"
#include "mgr/StringParam.h"

Mgr::QueryParam::Pointer
Mgr::QueryParams::get(const String& name) const
{
    Must(name.size() != 0);
    Params::const_iterator pos = find(name);
    return (pos == params.end() ? NULL : pos->second);
}

void
Mgr::QueryParams::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.putInt(params.size());
    for (Params::const_iterator iter = params.begin(); iter != params.end(); ++iter) {
        Must(iter->first.size() != 0);
        msg.putString(iter->first);
        Must(iter->second != NULL);
        iter->second->pack(msg);
    }
}

void
Mgr::QueryParams::unpack(const Ipc::TypedMsgHdr& msg)
{
    int count = msg.getInt();
    Must(count >= 0);
    params.clear();
    for ( ; count > 0; --count) {
        String name;
        msg.getString(name);
        Must(name.size() != 0);
        QueryParam::Type type;
        msg.getPod(type);
        QueryParam::Pointer value = CreateParam(type);
        value->unpackValue(msg);
        params.push_back(Param(name, value));
    }
}

Mgr::QueryParams::Params::const_iterator
Mgr::QueryParams::find(const String& name) const
{
    Must(name.size() != 0);
    Params::const_iterator iter = params.begin();
    for ( ; iter != params.end(); ++iter) {
        if (name.caseCmp(iter->first) == 0)
            break;
    }
    return iter;
}

bool
Mgr::QueryParams::ParseParam(const String& paramStr, Param& param)
{
    bool parsed = false;
    regmatch_t pmatch[3];
    regex_t intExpr;
    regcomp(&intExpr, "^([a-z][a-z0-9_]*)=([0-9]+((,[0-9]+))*)$", REG_EXTENDED | REG_ICASE);
    regex_t stringExpr;
    regcomp(&stringExpr, "^([a-z][a-z0-9_]*)=([^&= ]+)$", REG_EXTENDED | REG_ICASE);
    if (regexec(&intExpr, paramStr.termedBuf(), 3, pmatch, 0) == 0) {
        param.first = paramStr.substr(pmatch[1].rm_so, pmatch[1].rm_eo);
        std::vector<int> array;
        int n = pmatch[2].rm_so;
        for (int i = n; i < pmatch[2].rm_eo; ++i) {
            if (paramStr[i] == ',') {
                array.push_back(atoi(paramStr.substr(n, i).termedBuf()));
                n = i + 1;
            }
        }
        if (n < pmatch[2].rm_eo)
            array.push_back(atoi(paramStr.substr(n, pmatch[2].rm_eo).termedBuf()));
        param.second = new IntParam(array);
        parsed = true;
    } else if (regexec(&stringExpr, paramStr.termedBuf(), 3, pmatch, 0) == 0) {
        param.first = paramStr.substr(pmatch[1].rm_so, pmatch[1].rm_eo);
        param.second = new StringParam(paramStr.substr(pmatch[2].rm_so, pmatch[2].rm_eo));
        parsed = true;
    }
    regfree(&stringExpr);
    regfree(&intExpr);
    return parsed;
}

bool
Mgr::QueryParams::Parse(const String& aParamsStr, QueryParams& aParams)
{
    if (aParamsStr.size() != 0) {
        Param param;
        size_t n = 0;
        size_t len = aParamsStr.size();
        for (size_t i = n; i < len; ++i) {
            if (aParamsStr[i] == '&') {
                if (!ParseParam(aParamsStr.substr(n, i), param))
                    return false;
                aParams.params.push_back(param);
                n = i + 1;
            }
        }
        if (n < len) {
            if (!ParseParam(aParamsStr.substr(n, len), param))
                return false;
            aParams.params.push_back(param);
        }
    }
    return true;
}

Mgr::QueryParam::Pointer
Mgr::QueryParams::CreateParam(QueryParam::Type aType)
{
    switch (aType) {
    case QueryParam::ptInt:
        return new IntParam();

    case QueryParam::ptString:
        return new StringParam();

    default:
        throw TexcHere("unknown parameter type");
        break;
    }
    return NULL;
}

