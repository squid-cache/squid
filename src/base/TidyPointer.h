/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_TIDYPOINTER_H
#define SQUID_BASE_TIDYPOINTER_H

/**
 * A pointer that deletes the object it points to when the pointer's owner or
 * context is gone. Similar to std::unique_ptr but without confusing assignment
 * and with a customizable cleanup method. Prevents memory leaks in
 * the presence of exceptions and processing short cuts.
*/
template <typename T, void (*DeAllocator)(T *t)> class TidyPointer
{
public:
    /// Delete callback.
    typedef void DCB (T *t);
    TidyPointer(T *t = NULL)
        :   raw(t) {}
public:
    bool operator !() const { return !raw; }
    /// Returns raw and possibly NULL pointer
    T *get() const { return raw; }
    /// Address of the raw pointer, for pointer-setting functions
    T **addr() { return &raw; }
    /// Reset raw pointer - delete last one and save new one.
    void reset(T *t) {
        deletePointer();
        raw = t;
    }

    /// Forget the raw pointer without freeing it. Become a nil pointer.
    T *release() {
        T *ret = raw;
        raw = NULL;
        return ret;
    }
    /// Deallocate raw pointer.
    ~TidyPointer() {
        deletePointer();
    }
private:
    /// Forbidden copy constructor.
    TidyPointer(TidyPointer<T, DeAllocator> const &);
    /// Forbidden assigment operator.
    TidyPointer <T, DeAllocator> & operator = (TidyPointer<T, DeAllocator> const &);
    /// Deallocate raw pointer. Become a nil pointer.
    void deletePointer() {
        if (raw) {
            DeAllocator(raw);
        }
        raw = NULL;
    }
    T *raw; ///< pointer to T object or NULL
};

/// DeAllocator for pointers that need free(3) from the std C library
template<typename T> void tidyFree(T *p)
{
    xfree(p);
}

#endif // SQUID_BASE_TIDYPOINTER_H

