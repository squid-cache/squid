#!/bin/sh

# This script requires $PULL_REQUEST_NUMBER for testing PR commits

# Whether the branch has a commit with a message matching the given regex.
# The first argument is the SHA of the primary commit with the desired change.
# We want to find up/backported commits that will have different SHAs and that
# may have minor commit message variations, so that SHA is for reference only.
has_commit_by_message_() {
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

check_functionality_client_certificate_handling() {
    if ! fgrep -q master_xaction src/cf.data.pre
    then
        echo "No client certificate handling tests for Squid v4 and older";
        return 0;
    fi

    if git grep -q SSL_MODE_NO_AUTO_CHAIN src/
    then
        echo "No client certificate handling tests with SSL_MODE_NO_AUTO_CHAIN (yet)";
        return 0;
    fi

    wget https://www.measurement-factory.com/extras/fc128.tgz
    tar -xvzf fc128.tgz
    sudo ./fc128-sending-clientca-to-clients/test-client-cert-handling.pl
    return 0;
}

start_overlord_() {
    if test -e squid-overlord.log && curl -H 'Pop-Version: 4' --no-progress-meter http://localhost:13128/check > /dev/null
    then
        return 0;
    fi

    local url=https://github.com/measurement-factory/squid-overlord/raw/stable2/overlord.pl
    # XXX: Github actions runners prohibit ulimit -c unlimited.
    curl -sSL $url | sed 's/-c unlimited/-n 10240/' | sudo -n --background -u nobody perl - > squid-overlord.log 2>&1
}

run_daft_test_() {
    testId="$1"

    start_overlord_ || return

    local runner=${DAFT_MAIN:=extras/daft/src/cli/daft.js}
    if ! test -e $runner
    then
        echo "::error ::Missing Daft tool"
        echo "Expected to find it in $runner"
        exit 1;
    fi

    local testsDir=${SQUID_DAFT_TESTS_DIR:=extras/squid-dafts/tests/}
    if ! test -d $testsDir
    then
        echo "::error ::Missing collection of Squid-specific Daft tests"
        echo "Expected to find them in $testsDir"
        exit 1;
    fi

    local testScript=$testsDir/$testId.js
    if ! test -e $testScript
    then
        echo "::error ::Unknown test requested: $testId"
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
    echo "::error ::Test $testId: Failed with exit code $result:"
    echo "::group::$testId.log tail"
    tail -n 100 $testId.log
    echo "::endgroup::"

    # TODO: Link to the artifact
    echo "See $testId.log (tailed above) for failure details"
    return $result
}

check_pconn() {
    run_daft_test_ pconn
}

check_busy_restart() {
    if ! run_daft_test_ busy-restart
    then
        # XXX: Make the test stable instead!
        echo "::warning ::Ignoring unstable test failure: busy-restart"
    fi
    return 0
}

check_proxy_collapsed_forwarding() {
    if ! has_commit_by_message_ 1af789e 'Do not stall if xactions overwrite a recently active'
    then
        echo "No proxy-collapsed-forwarding due to stalling transactions"
        return 0;
    fi
    run_daft_test_ proxy-collapsed-forwarding
}

check_proxy_update_headers_after_304() {
    if egrep 'AC_INIT.*Proxy.,.[1234][.]' configure.ac
    then
        echo "No proxy-update-headers-after-304 until v5";
        return 0;
    fi
    run_daft_test_ proxy-update-headers-after-304
}

check_upgrade_protocols() {
    if ! fgrep -q http_upgrade_request_protocols src/cf.data.pre
    then
        echo "No upgrade-protocols without http_upgrade_request_protocols support";
        return 0;
    fi
    run_daft_test_ upgrade-protocols
}

run_one_test_() {
    testName=$1

    # convert a test name foo into a check_foo() function name
    # e.g. busy-restart becomes check_busy_restart
    check=`echo $testName | sed s/-/_/g`

    check_$check
}

run_tests_() {
    result=0
    failed_tests=""
    for testName in "$@"
    do
        if run_one_test_ $testName
        then
            continue;
        else
            result=$?
            failed_tests="$failed_tests $testName"
        fi
    done

    if test -n "$failed_tests"
    then
        echo "::error ::Failed check(s):$failed_tests"
    fi
    return $result
}

if test -n "$2"
then
    run_tests_ "$@"
    exit $?
fi

if test -n "$1"
then
    # run a single test specified by the lonely command line argument
    # this simplifies diagnostics/output in case of failures
    run_one_test_ "$1"
    exit $?
fi

default_tests="
    pconn
    proxy-update-headers-after-304
    upgrade-protocols
    proxy-collapsed-forwarding
    busy-restart
"
run_tests_ $default_tests
