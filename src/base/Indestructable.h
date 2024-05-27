/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_INDESTRUCTABLE_H
#define SQUID_SRC_BASE_INDESTRUCTABLE_H

/// XXX: Sandbox: https://godbolt.org/z/PqcWGKWsM

/// An object wrapper that prevents wrapped object destruction. This "leaky"
/// class is meant for use with data members inside legacy globals like Config
/// that do not need to be destructed and which destruction would cause
/// problems. For example, this wrapper is necessary to store RefCount<T>
/// objects in Config global without #including all of T declarations in
/// SquidConfig.cc (where that Config global is destructed).
template <class T>
class Indestructable
{
public:
    operator T &() { return storage.object; }
    operator const T &() const { return storage.object; }
    auto operator !() { return !storage.object; }
    auto operator ->() const { return storage.object.operator ->(); }
    auto &operator *() const { return storage.object.operator *(); }
    auto &operator =(const T &obj) { storage.object = obj; return *this; }
    explicit operator bool() const { return storage.object.operator bool(); }
    template <typename Other>
    auto operator ==(const Other &other) const { return storage.object.operator ==(other); }
    template <typename Other>
    auto operator !=(const Other &other) const { return storage.object.operator !=(other); }

    // C++ union suppresses automatic data member constructor/destructor calls
    union U {
        U() { new(&object) T(); } // placement-new default-initializes object
        ~U() {} // required for C++ unions with members having custom destructors
        T object; ///< stored object that is never destroyed
    } storage;
};

#endif /* SQUID_SRC_BASE_INDESTRUCTABLE_H */

