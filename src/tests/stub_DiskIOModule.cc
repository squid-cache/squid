/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "DiskIOModule.cc"
#include "tests/STUB.h"

#include "DiskIO/DiskIOModule.h"

#include <vector>

void DiskIOModule::SetupAllModules() STUB
void DiskIOModule::ModuleAdd(DiskIOModule &) STUB
void DiskIOModule::FreeAllModules() STUB
void DiskIOModule::PokeAllModules() STUB
DiskIOModule *DiskIOModule::Find(char const *) STUB_RETVAL(NULL)
DiskIOModule *DiskIOModule::FindDefault() STUB_RETVAL(NULL)
std::vector<DiskIOModule*> const &DiskIOModule::Modules() STUB_RETSTATREF(std::vector<DiskIOModule*>)

