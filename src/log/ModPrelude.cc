/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 50    Log file handling
 * AUTHOR: CSSI (Selim Menouar, Verene Houdebine)
 */

#include "squid.h"
#include "disk.h"
#include "fatal.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "log/File.h"
#include "log/ModPrelude.h"
#include "SquidConfig.h"

#include <cerrno>

#ifndef PRELUDE
int
logfile_mod_prelude_open(Logfile * lf, const char *analyzer_name, size_t bufsz, int fatal_flag)
{
    debugs(50, false, "You have to compile with libprelude using ./configure --enable-prelude");
    return 0;
}

#else

#include <libprelude/prelude.h>

#define ANALYZER_MODEL "Squid"
#define ANALYZER_CLASS "Proxy"
#define ANALYZER_MANUFACTURER "http://www.squid-cache.org"

int idmef_analyzer_setup(idmef_analyzer_t *analyzer, const char *analyzer_name){
    int ret;
    prelude_string_t *str;

    /* alert->analyzer->name */
    ret = idmef_analyzer_new_name(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, analyzer_name);

    /* alert->analyzer->model */
    ret = idmef_analyzer_new_model(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, ANALYZER_MODEL);

    /* alert->analyzer->class */
    ret = idmef_analyzer_new_class(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, ANALYZER_CLASS);

    /* alert->analyzer->manufacturer */
    ret = idmef_analyzer_new_manufacturer(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, ANALYZER_MANUFACTURER);

    /* alert->analyzer->version */
    ret = idmef_analyzer_new_version(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, VERSION);

    return 0;
}

static void
logfile_mod_prelude_writeline(Logfile * lf, const char *buf, size_t len)
{
}

static void
logfile_mod_prelude_linestart(Logfile *)
{
}

static void
logfile_mod_prelude_lineend(Logfile * lf)
{
}

static void
logfile_mod_prelude_flush(Logfile * lf)
{
}

static void
logfile_mod_prelude_rotate(Logfile * lf, const int16_t nRotate)
{
}

static void
logfile_mod_prelude_close(Logfile * lf)
{
    prelude_client_t *prelude_client = (prelude_client_t *) lf->data;
    prelude_client_destroy(prelude_client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
}

/*
 * This code expects the path to be a writable filename
 */
int
logfile_mod_prelude_open(Logfile * lf, const char *analyzer_name, size_t bufsz, int fatal_flag)
{
    int ret;
    prelude_client_t * prelude_client;

    lf->f_close = logfile_mod_prelude_close;
    lf->f_linewrite = logfile_mod_prelude_writeline;
    lf->f_linestart = logfile_mod_prelude_linestart;
    lf->f_lineend = logfile_mod_prelude_lineend;
    lf->f_flush = logfile_mod_prelude_flush;
    lf->f_rotate = logfile_mod_prelude_rotate;

    prelude_client = NULL;

    ret = prelude_init(0, NULL);
    if ( ret < 0 )  {
        debugs(50, DBG_IMPORTANT,"Unable to initialize the prelude library : " << prelude_strerror(ret));
        return -1;
    }


    ret = prelude_client_new(&prelude_client, analyzer_name);
    if ( ret < 0 )  {
        debugs(50, DBG_IMPORTANT,"Unable to create a prelude client object :" << prelude_strerror(ret));
        return -1;
    }

    ret = idmef_analyzer_setup(prelude_client_get_analyzer(prelude_client), analyzer_name);
    if ( ret < 0 )  {
        debugs(50, DBG_IMPORTANT, prelude_strerror(ret));
        return -1;
    }

    ret = prelude_client_start(prelude_client);
    if ( ret < 0 || ! prelude_client ) {
        debugs(50, DBG_IMPORTANT,"Unable to start prelude client"<< prelude_strerror(ret));
        prelude_client_destroy(prelude_client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
        return -1;
    }

    lf->data = prelude_client;

    return 1;
}
#endif
