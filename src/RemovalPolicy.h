/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef   SQUID_REMOVALPOLICY_H
#define   SQUID_REMOVALPOLICY_H

#include "cbdata.h"

class RemovalPolicyWalker;
class RemovalPurgeWalker;

class RemovalPolicySettings
{

public:
    RemovalPolicySettings() : type(NULL), args(NULL) {};

    char *type;
    wordlist *args;
};

class RemovalPolicyNode
{

public:
    RemovalPolicyNode() : data(NULL) {}

    void *data;
};

class RemovalPolicy
{
public:
    const char *_type;
    void *_data;
    void (*Free) (RemovalPolicy * policy);
    void (*Add) (RemovalPolicy * policy, StoreEntry * entry, RemovalPolicyNode * node);
    void (*Remove) (RemovalPolicy * policy, StoreEntry * entry, RemovalPolicyNode * node);
    void (*Referenced) (RemovalPolicy * policy, const StoreEntry * entry, RemovalPolicyNode * node);
    void (*Dereferenced) (RemovalPolicy * policy, const StoreEntry * entry, RemovalPolicyNode * node);
    RemovalPolicyWalker *(*WalkInit) (RemovalPolicy * policy);
    RemovalPurgeWalker *(*PurgeInit) (RemovalPolicy * policy, int max_scan);
    void (*Stats) (RemovalPolicy * policy, StoreEntry * entry);
private:
    CBDATA_CLASS2(RemovalPolicy);
};

class RemovalPolicyWalker
{
public:
    RemovalPolicy *_policy;
    void *_data;
    const StoreEntry *(*Next) (RemovalPolicyWalker * walker);
    void (*Done) (RemovalPolicyWalker * walker);
private:
    CBDATA_CLASS2(RemovalPolicyWalker);
};

class RemovalPurgeWalker
{
public:
    RemovalPolicy *_policy;
    void *_data;
    int scanned, max_scan, locked;
    StoreEntry *(*Next) (RemovalPurgeWalker * walker);
    void (*Done) (RemovalPurgeWalker * walker);
private:
    CBDATA_CLASS2(RemovalPurgeWalker);
};

RemovalPolicy *createRemovalPolicy(RemovalPolicySettings * settings);

typedef RemovalPolicy *REMOVALPOLICYCREATE(wordlist * args);

#endif /* SQUID_REMOVALPOLICY_H */

