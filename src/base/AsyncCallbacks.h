/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_ASYNCCALLBACKS_H
#define SQUID_SRC_BASE_ASYNCCALLBACKS_H

#include "base/AsyncCall.h"
#include "base/AsyncJobCalls.h"
#include "base/TypeTraits.h"

/// access to a callback result carried by an asynchronous CallDialer
template <typename AnswerT>
class WithAnswer
{
public:
    using Answer = AnswerT;

    virtual ~WithAnswer() = default;

    /// callback results setter
    virtual Answer &answer() = 0;
};

/// a smart AsyncCall pointer for delivery of future results
template <typename Answer>
class AsyncCallback
{
public:
    // all generated copying/moving functions are correct
    AsyncCallback() = default;

    template <class Call>
    explicit AsyncCallback(const RefCount<Call> &call):
        call_(call),
        answer_(&(call->dialer.answer()))
    {
    }

    Answer &answer()
    {
        assert(answer_);
        return *answer_;
    }

    /// make this smart pointer nil
    /// \return the AsyncCall pointer we used to manage before this call
    AsyncCall::Pointer release()
    {
        answer_ = nullptr;
        const auto call = call_;
        call_ = nullptr;
        return call;
    }

    /// whether the callback has been set but not released
    explicit operator bool() const { return answer_; }

    /* methods for decaying into an AsyncCall pointer w/o access to answer */
    operator const AsyncCall::Pointer &() const { return call_; }
    const AsyncCall &operator *() const { return call_.operator*(); }
    const AsyncCall *operator ->() const { return call_.operator->(); }

private:
    /// callback carrying the answer
    AsyncCall::Pointer call_;

    /// (future) answer inside this->call, obtained when it was still possible
    /// to reach it without dynamic casts and virtual methods
    Answer *answer_ = nullptr;
};

/// CallDialer for single-parameter callback functions
template <typename Argument1>
class UnaryFunCallbackDialer:
    public CallDialer,
    public WithAnswer<Argument1>
{
public:
    // stand-alone function that receives our answer
    using Handler = void (Argument1 &);

    explicit UnaryFunCallbackDialer(Handler * const aHandler): handler(aHandler) {}
    ~UnaryFunCallbackDialer() override = default;

    /* CallDialer API */
    bool canDial(AsyncCall &) { return bool(handler); }
    void dial(AsyncCall &) { handler(arg1); }
    void print(std::ostream &os) const final { os << '(' << arg1 << ')'; }

    /* WithAnswer API */
    Argument1 &answer() final { return arg1; }

private:
    Handler *handler; ///< the function to call
    Argument1 arg1; ///< actual call parameter
};

/// CallDialer for single-parameter callback methods of cbdata-protected classes
/// that are not AsyncJobs (use UnaryJobCallbackDialer for the latter).
template <class Destination, typename Argument1>
class UnaryCbcCallbackDialer:
    public CallDialer,
    public WithAnswer<Argument1>
{
public:
    // class member function that receives our answer
    typedef void (Destination::*Method)(Argument1 &);

    UnaryCbcCallbackDialer(Method method, Destination *destination): destination_(destination), method_(method) {}
    ~UnaryCbcCallbackDialer() override = default;

    /* CallDialer API */
    bool canDial(AsyncCall &) { return destination_.valid(); }
    void dial(AsyncCall &) {((*destination_).*method_)(arg1_); }
    void print(std::ostream &os) const final { os << '(' << arg1_ << ')'; }

    /* WithAnswer API */
    Argument1 &answer() final { return arg1_; }

private:
    CbcPointer<Destination> destination_; ///< object to deliver the answer to
    Method method_; ///< Destination method to call with the answer
    Argument1 arg1_;
};

/// CallDialer for single-parameter callback methods of AsyncJob classes.
/// \sa UnaryCbcCallbackDialer and UnaryFunCallbackDialer.
template <class Job, typename Argument1>
class UnaryJobCallbackDialer:
    public UnaryMemFunT<Job, Argument1, Argument1&>,
    public WithAnswer<Argument1>
{
public:
    using Base = UnaryMemFunT<Job, Argument1, Argument1&>;

    UnaryJobCallbackDialer(const CbcPointer<Job> &aJob, typename Base::Method aMethod):
        Base(aJob, aMethod, {}) {}

    /* WithAnswer API */
    Argument1 &answer() final { return this->arg1; }
};

/// whether the given type is an AsyncJob
/// reduces code duplication in declarations further below
template <typename T>
using IsAsyncJob = typename std::conditional<
                   std::is_base_of<AsyncJob, T>::value,
                   std::true_type,
                   std::false_type
                   >::type;

/// helper function to simplify UnaryCbcCallbackDialer creation
template <class Destination, typename Argument1, std::enable_if_t<!IsAsyncJob<Destination>::value, int> = 0>
UnaryCbcCallbackDialer<Destination, Argument1>
callbackDialer(void (Destination::*method)(Argument1 &), Destination * const destination)
{
    static_assert(!std::is_base_of<AsyncJob, Destination>::value, "wrong wrapper");
    return UnaryCbcCallbackDialer<Destination, Argument1>(method, destination);
}

/// helper function to simplify UnaryJobCallbackDialer creation
template <class Destination, typename Argument1, std::enable_if_t<IsAsyncJob<Destination>::value, int> = 0>
UnaryJobCallbackDialer<Destination, Argument1>
callbackDialer(void (Destination::*method)(Argument1 &), Destination * const destination)
{
    static_assert(std::is_base_of<AsyncJob, Destination>::value, "wrong wrapper");
    return UnaryJobCallbackDialer<Destination, Argument1>(destination, method);
}

/// helper function to simplify UnaryFunCallbackDialer creation
template <typename Argument1>
UnaryFunCallbackDialer<Argument1>
callbackDialer(void (*destination)(Argument1 &))
{
    return UnaryFunCallbackDialer<Argument1>(destination);
}

/// helper function to create an AsyncCallback object that matches an AsyncCall
/// based on a WithAnswer answer dialer.
template <class Call>
AsyncCallback<typename Call::Dialer::Answer>
AsyncCallback_(const RefCount<Call> &call)
{
    return AsyncCallback<typename Call::Dialer::Answer>(call);
}

/// AsyncCall for calling back a class method compatible with
/// callbackDialer(). TODO: Unify with JobCallback() which requires dialers
/// that feed the job pointer to the non-default CommCommonCbParams constructor.
#define asyncCallback(dbgSection, dbgLevel, method, object) \
    AsyncCallback_(asyncCall((dbgSection), (dbgLevel), #method, \
        callbackDialer(&method, (object))))

// TODO: Use C++20 __VA_OPT__ to merge this with asyncCallback().
/// AsyncCall for calling back a function
#define asyncCallbackFun(dbgSection, dbgLevel, function) \
    AsyncCallback_(asyncCall((dbgSection), (dbgLevel), #function, \
        callbackDialer(&function)))

#endif /* SQUID_SRC_BASE_ASYNCCALLBACKS_H */

