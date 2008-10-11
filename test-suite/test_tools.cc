/*
 * $Id: test_tools.cc,v 1.11 2008/02/26 18:52:54 rousskov Exp $
 */

// XXX: This file is made of large pieces of src/debug.cc and src/tools.cc
// with only a few minor modifications. TODO: redesign or delete.

#define _SQUID_EXTERNNEW_
#include "squid.h"
#include <iostream>
#include <sstream>

/* AYJ: the debug stuff here should really be in a stub_debug.cc file for tests to link */

/* for correct pre-definitions of debug objects */
#include "Debug.h"

FILE *debug_log = NULL;

void
xassert(const char *msg, const char *file, int line)
{
    std::cout << "Assertion failed: (" << msg << ") at " << file << ":" << line << std::endl;
    exit (1);
}

int Debug::Levels[MAX_DEBUG_SECTIONS];
int Debug::level;

static void
_db_print_stderr(const char *format, va_list args);

void
#if STDC_HEADERS
_db_print(const char *format,...)
{
#else
_db_print(va_alist)
va_dcl {
    const char *format = NULL;
#endif

    LOCAL_ARRAY(char, f, BUFSIZ);
    va_list args1;
#if STDC_HEADERS

    va_list args2;
    va_list args3;
#else
#define args2 args1
#define args3 args1
#endif

#if STDC_HEADERS

    va_start(args1, format);

    va_start(args2, format);

    va_start(args3, format);

#else

    format = va_arg(args1, const char *);

#endif

    snprintf(f, BUFSIZ, "%s| %s",
             "stub time", //debugLogTime(squid_curtime),
             format);

    _db_print_stderr(f, args2);

    va_end(args1);

#if STDC_HEADERS

    va_end(args2);

    va_end(args3);

#endif
}

static void
_db_print_stderr(const char *format, va_list args) {
    /* FIXME? */
    // if (opt_debug_stderr < Debug::level)

    if (1 < Debug::level)
        return;

    vfprintf(stderr, format, args);
}

void
fatal_dump(const char *message) {
    debug (0,0) ("Fatal: %s",message);
    exit (1);
}

void
fatal(const char *message) {
    debug (0,0) ("Fatal: %s",message);
    exit (1);
}

/* used by fatalf */
static void
fatalvf(const char *fmt, va_list args) {
    static char fatal_str[BUFSIZ];
    vsnprintf(fatal_str, sizeof(fatal_str), fmt, args);
    fatal(fatal_str);
}

/* printf-style interface for fatal */
#if STDC_HEADERS
void
fatalf(const char *fmt,...) {
    va_list args;
    va_start(args, fmt);
#else
void
fatalf(va_alist)
va_dcl {
    va_list args;
    const char *fmt = NULL;
    va_start(args);
    fmt = va_arg(args, char *);
#endif

    fatalvf(fmt, args);
    va_end(args);
}

void
debug_trap(const char *message) {
    fatal(message);
}

int Debug::TheDepth = 0;

std::ostream &
Debug::getDebugOut() {
    assert(TheDepth >= 0);
    ++TheDepth;
    if (TheDepth > 1) {
        assert(CurrentDebug);
        *CurrentDebug << std::endl << "reentrant debuging " << TheDepth << "-{";
    } else {
        assert(!CurrentDebug);
        CurrentDebug = new std::ostringstream();
        // set default formatting flags
        CurrentDebug->setf(std::ios::fixed);
        CurrentDebug->precision(2);
    }
    return *CurrentDebug;
}

void
Debug::finishDebug() {
    assert(TheDepth >= 0);
    assert(CurrentDebug);
    if (TheDepth > 1) {
        *CurrentDebug << "}-" << TheDepth << std::endl;
    } else {
        assert(TheDepth == 1);
        _db_print("%s\n", CurrentDebug->str().c_str());
        delete CurrentDebug;
        CurrentDebug = NULL;
    }
    --TheDepth;
}

void
Debug::xassert(const char *msg, const char *file, int line) {

    if (CurrentDebug) {
        *CurrentDebug << "assertion failed: " << file << ":" << line <<
        ": \"" << msg << "\"";
    }
    abort();
}

std::ostringstream *Debug::CurrentDebug (NULL);

MemAllocator *dlink_node_pool = NULL;

dlink_node *
dlinkNodeNew() {
    if (dlink_node_pool == NULL)
        dlink_node_pool = memPoolCreate("Dlink list nodes", sizeof(dlink_node));

    /* where should we call memPoolDestroy(dlink_node_pool); */
    return static_cast<dlink_node *>(dlink_node_pool->alloc());
}

/* the node needs to be unlinked FIRST */
void
dlinkNodeDelete(dlink_node * m) {
    if (m == NULL)
        return;

    dlink_node_pool->free(m);
}

void
dlinkAdd(void *data, dlink_node * m, dlink_list * list) {
    m->data = data;
    m->prev = NULL;
    m->next = list->head;

    if (list->head)
        list->head->prev = m;

    list->head = m;

    if (list->tail == NULL)
        list->tail = m;
}

void
dlinkAddAfter(void *data, dlink_node * m, dlink_node * n, dlink_list * list) {
    m->data = data;
    m->prev = n;
    m->next = n->next;

    if (n->next)
        n->next->prev = m;
    else {
        assert(list->tail == n);
        list->tail = m;
    }

    n->next = m;
}

void
dlinkAddTail(void *data, dlink_node * m, dlink_list * list) {
    m->data = data;
    m->next = NULL;
    m->prev = list->tail;

    if (list->tail)
        list->tail->next = m;

    list->tail = m;

    if (list->head == NULL)
        list->head = m;
}

void
dlinkDelete(dlink_node * m, dlink_list * list) {
    if (m->next)
        m->next->prev = m->prev;

    if (m->prev)
        m->prev->next = m->next;

    if (m == list->head)
        list->head = m->next;

    if (m == list->tail)
        list->tail = m->prev;

    m->next = m->prev = NULL;
}

Ctx
ctx_enter(const char *descr) {
    return 0;
}

void
ctx_exit(Ctx ctx) {}
