/*
 * 2008/11/14
 */

#include "config.h"
#include "ssl/Config.h"
#include "ssl/helper.h"
#include "SquidTime.h"
#include "SwapDir.h"

Ssl::Helper * Ssl::Helper::GetInstance()
{
    static Ssl::Helper sslHelper;
    return &sslHelper;
}

Ssl::Helper::Helper()
{
    Init();
}

Ssl::Helper::~Helper()
{
    Shutdown();
}

void Ssl::Helper::Init()
{
    if (ssl_crtd == NULL)
        ssl_crtd = helperCreate("ssl_crtd");
    ssl_crtd->n_to_start = Ssl::TheConfig.ssl_crtd_n_running;
    ssl_crtd->ipc_type = IPC_STREAM;
    // The crtd messages may contain the eol ('\n') character. We are
    // going to use the '\1' char as the end-of-message mark.
    ssl_crtd->eom = '\1';
    assert(ssl_crtd->cmdline == NULL);
    {
        char *tmp = xstrdup(Ssl::TheConfig.ssl_crtd);
        char *tmp_begin = tmp;
        char * token = NULL;
        bool db_path_was_found = false;
        bool block_size_was_found = false;
        char buffer[20] = "2048";
        while ((token = strwordtok(NULL, &tmp))) {
            wordlistAdd(&ssl_crtd->cmdline, token);
            if (!strcmp(token, "-b"))
                block_size_was_found = true;
            if (!strcmp(token, "-s")) {
                db_path_was_found = true;
            } else if (db_path_was_found) {
                db_path_was_found = false;
                int fs_block_size = 0;
                storeDirGetBlkSize(token, &fs_block_size);
                snprintf(buffer, sizeof(buffer), "%i", fs_block_size);
            }
        }
        if (!block_size_was_found) {
            wordlistAdd(&ssl_crtd->cmdline, "-b");
            wordlistAdd(&ssl_crtd->cmdline, buffer);
        }
        safe_free(tmp_begin);
    }
    helperOpenServers(ssl_crtd);
}

void Ssl::Helper::Shutdown()
{
    if (!ssl_crtd)
        return;
    helperShutdown(ssl_crtd);
    wordlistDestroy(&ssl_crtd->cmdline);
    if (!shutting_down)
        return;
    helperFree(ssl_crtd);
    ssl_crtd = NULL;
}

void Ssl::Helper::sslSubmit(CrtdMessage const & message, HLPCB * callback, void * data)
{
    static time_t first_warn = 0;

    if (ssl_crtd->stats.queue_size >= (int)(ssl_crtd->n_running * 2)) {
        if (first_warn == 0)
            first_warn = squid_curtime;
        if (squid_curtime - first_warn > 3 * 60)
            fatal("SSL servers not responding for 3 minutes");
        debugs(34, 1, HERE << "Queue overload, rejecting");
        callback(data, (char *)"error 45 Temporary network problem, please retry later");
        return;
    }

    first_warn = 0;
    std::string msg = message.compose();
    msg += '\n';
    helperSubmit(ssl_crtd, msg.c_str(), callback, data);
}
