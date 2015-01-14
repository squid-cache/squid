/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_MGR_CACHEMGRPASSWD_H_
#define SQUID_MGR_CACHEMGRPASSWD_H_

class wordlist;

namespace Mgr
{
//TODO: refactor into a std::list
/// list of cachemgr password authorization definitions. Currently a POD.
class ActionPasswordList
{
public:
    ActionPasswordList() : passwd(NULL), actions(NULL), next(NULL) {}
    ~ActionPasswordList();

    char *passwd;
    wordlist *actions;
    ActionPasswordList *next;
};

} //namespace Mgr

#endif /* SQUID_MGR_CACHEMGRPASSWD_H_ */

