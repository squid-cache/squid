/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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

#include <regex>

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
    std::regex intExpr("^([a-z][a-z0-9_]*)=([0-9]+((,[0-9]+))*)$", std::regex::extended | std::regex::icase);
    std::regex stringExpr("^([a-z][a-z0-9_]*)=([^&= ]+)$", std::regex::extended | std::regex::icase);
    std::smatch pmatch;

    std::string temp(paramStr.termedBuf());
    if (std::regex_match(temp, pmatch, intExpr)) {

        auto itr = pmatch.begin();
        ++itr; // move to [1] - first actual sub-match

        // match [1] is the key name
        param.first = itr->str().c_str();
        ++itr;

        // match [2] and later are a series of N,N,N,N,N values
        std::vector<int> array;
        while (itr != pmatch.end()) {
            if (itr->str().c_str()[0] == ',')
                array.push_back(atoi(itr->str().c_str()+1));
            else
                array.push_back(atoi(itr->str().c_str()));
            ++itr;
        }
        param.second = new IntParam(array);
        return true;
    }

    if (std::regex_match(temp, pmatch, stringExpr)) {
        param.first = pmatch[1].str().c_str();
        param.second = new StringParam(pmatch[2].str().c_str());
        return true;
    }

    return false;
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

