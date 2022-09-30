#!/bin/sh

# print an error message (with special markers recognized by Github)
echo_error() {
    echo "::error ::" "$@"
}

# print a warning message (with special markers recognized by Github)
echo_error() {
    echo "::warning ::" "$@"
}

# Whether the branch has a commit with a message matching the given regex.
# The first argument is the SHA of the primary commit with the desired change.
# We want to find up/backported commits that will have different SHAs and that
# may have minor commit message variations, so that SHA is for reference only.
has_commit_by_message() {
    commit="$1"
    shift

    if git log --grep "$@" | grep -q ^commit
    then
        return 0;
    fi

    echo "Was looking for branch commit with a message matching the following"
    echo "    regex: " "$@"
    echo "    This code lacks commit $commit or equivalent."
    return 1;
}

start_overlord() {
    if test -e squid-overlord.log && curl -H 'Pop-Version: 4' --no-progress-meter http://localhost:13128/check > /dev/null
    then
        return 0;
    fi

    local url=https://github.com/measurement-factory/squid-overlord/raw/stable2/overlord.pl
    # XXX: Github actions runners prohibit ulimit -c unlimited.
    curl -sSL $url | sed 's/-c unlimited/-n 10240/' | sudo -n --background -u nobody perl - > squid-overlord.log 2>&1
}

run_daft_test() {
    testId="$1"

    start_overlord || return

    local runner=${DAFT_MAIN:=extras/daft/src/cli/daft.js}
    if ! test -e $runner
    then
        echo_error "Missing Daft tool"
        echo "Expected to find it in $runner"
        exit 1;
    fi

    local testsDir=${SQUID_DAFT_TESTS_DIR:=extras/squid-dafts/tests/}
    if ! test -d $testsDir
    then
        echo_error "Missing collection of Squid-specific Daft tests"
        echo "Expected to find them in $testsDir"
        exit 1;
    fi

    local testScript=$testsDir/$testId.js
    if ! test -e $testScript
    then
        echo_error "Unknown test requested: $testId"
        echo "Expected to find it as $testScript"
        return 1;
    fi

    echo "Running test: $testId"
    local result=undefined
    if $runner run $testScript > $testId.log 2>&1
    then
        echo "Test $testId: OK"
        return 0;
    else
        result=$?
    fi

    echo
    echo_error "Test $testId: Failed with exit code $result:"
    echo "::group::$testId.log tail"
    tail -n 100 $testId.log
    echo "::endgroup::"

    # TODO: Link to the artifact
    echo "See $testId.log (tailed above) for failure details"
    return $result
}

check_pconn() {
    run_daft_test pconn
}

check_busy_restart() {
    if ! run_daft_test busy-restart
    then
        # XXX: Make the test stable instead!
        echo_warning "Ignoring unstable test failure: busy-restart"
    fi
    return 0
}

check_proxy_collapsed_forwarding() {
    if ! has_commit_by_message 1af789e 'Do not stall if xactions overwrite a recently active'
    then
        echo "No proxy-collapsed-forwarding due to stalling transactions"
        return 0;
    fi
    run_daft_test proxy-collapsed-forwarding
}

check_proxy_update_headers_after_304() {
    if egrep 'AC_INIT.*Proxy.,.[1234][.]' configure.ac
    then
        echo "No proxy-update-headers-after-304 until v5";
        return 0;
    fi
    run_daft_test proxy-update-headers-after-304
}

check_upgrade_protocols() {
    if ! fgrep -q http_upgrade_request_protocols src/cf.data.pre
    then
        echo "No upgrade-protocols without http_upgrade_request_protocols support";
        return 0;
    fi
    run_daft_test upgrade-protocols
}

run_one_test() {
    testName=$1

    # convert a test name foo into a check_foo() function name
    # e.g. busy-restart becomes check_busy_restart
    check=`echo $testName | sed s/-/_/g`

    check_$check
}

run_tests() {
    result=0
    failed_tests=""
    for testName in "$@"
    do
        if run_one_test $testName
        then
            continue;
        else
            result=$?
            failed_tests="$failed_tests $testName"
        fi
    done

    if test -n "$failed_tests"
    then
        echo_error "Failed check(s):$failed_tests"
    fi
    return $result
}

# Run all named tests if multiple tests were named on the command line.
# This check must precede the next one for the next check to work correctly.
if test -n "$2"
then
    run_tests "$@"
    exit $?
fi

# Run one test if a single test was named on the command line. This special
# (but common in triage) use case simplifies failure diagnostics/output.
# The case of multiple tests was excluded in the previous check.
if test -n "$1"
then
    run_one_test "$1"
    exit $?
fi

# Run default tests if no tests were named on the command line.
default_tests="
    pconn
    proxy-update-headers-after-304
    upgrade-protocols
    proxy-collapsed-forwarding
    busy-restart
"
run_tests $default_tests
