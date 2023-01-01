#!/bin/sh
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This script tests a few Squid functionality requirements.
# It is suitable for automated CI and manual testing.

# Default-set and report used environment variables:
# * the root directory for storing test tools and test artifacts.
echo "TMPDIR=${TMPDIR:=${RUNNER_TEMP:-/tmp}}"
# * directory for cloning git repositories containing various test tools
echo "CLONES_DIR=${CLONES_DIR:=$TMPDIR/clones}"
# * directories of cloned repositories
echo "DAFT_DIR=${DAFT_DIR:=$CLONES_DIR/daft}"
echo "SQUID_DAFTS_DIR=${SQUID_DAFTS_DIR:=$CLONES_DIR/squid-dafts}"
echo "SQUID_OVERLORD_DIR=${SQUID_OVERLORD_DIR:=$CLONES_DIR/squid-overlord}"

# print an error message (with special markers recognized by GitHub Actions)
echo_error() {
    echo "::error ::" "$@"
}

# print a warning message (with special markers recognized by GitHub Actions)
echo_warning() {
    echo "::warning ::" "$@"
}

run() {
    echo "running: $@"
    "$@"
}

# Whether the branch has a commit with a message matching the given regex.
# The first argument is the SHA of the primary commit with the desired change.
# We want to find up/backported commits that will have different SHAs and that
# may have minor commit message variations, so that SHA is for reference only.
has_commit_by_message() {
    local commit="$1"
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

clone_repo() {
    local repo_url="$1"
    local destination_dir="$2"

    if test -e $destination_dir
    then
        echo "Skipping already fetched $destination_dir"
    elif run git clone --no-tags --quiet --depth=1 --branch production -- "$repo_url" "$destination_dir"
    then
        if test -e "$destination_dir/package.json"
        then
            ( cd $destination_dir && run npm install --no-audit --no-save ) || return
        fi
    else
        echo_error "Failed to fetch $repo_url into $destination_dir"
        return 1
    fi

    (cd $destination_dir && echo "Using commit `git rev-parse HEAD`")
}

start_overlord() {
    local url=http://localhost:13128/
    local log=$TMPDIR/squid-overlord.log
    if test -e $log && curl -H 'Pop-Version: 4' --no-progress-meter $url/check > /dev/null
    then
        echo "Will reuse squid-overlord service running at $url"
        return 0;
    fi

    # Do not be tempted to simply run `sudo ... overlord.pl`: User nobody will
    # lack read permissions, and sudo will ask for a password.
    sudo -n --background -u nobody perl < $SQUID_OVERLORD_DIR/overlord.pl > $log 2>&1 || return
    echo "Started squid-overlord service at $url"
}

setup_test_tools() {
    echo "::group::Setup test tools"

    clone_repo https://github.com/measurement-factory/daft $DAFT_DIR || return
    clone_repo https://github.com/measurement-factory/squid-dafts $SQUID_DAFTS_DIR || return
    clone_repo https://github.com/measurement-factory/squid-overlord $SQUID_OVERLORD_DIR || return

    if ! test -e $SQUID_DAFTS_DIR/src
    then
        run ln -s `realpath $DAFT_DIR/src` $SQUID_DAFTS_DIR/src || return
    fi
    if ! test -e $SQUID_DAFTS_DIR/node_modules
    then
        run ln -s `realpath $DAFT_DIR/node_modules` $SQUID_DAFTS_DIR/node_modules || return
    fi

    start_overlord || return

    # TODO: Find a good way to end group on (currently fatal) errors as well.
    echo "::endgroup::"
}

# executes a single test after the caller confirms that the test is applicable
run_confirmed_test() {
    local testId="$1"

    local testRunner="$DAFT_DIR/src/cli/daft.js"
    if ! test -e $testRunner
    then
        echo_error "Missing Daft test execution script"
        echo "Expected to find it at $testRunner"
        exit 1;
    fi

    local testsDir="$SQUID_DAFTS_DIR/tests"
    if ! test -d $testsDir
    then
        echo_error "Missing collection of Squid-specific Daft tests"
        echo "Expected to find them in $testsDir/"
        exit 1;
    fi

    local testScript=$testsDir/$testId.js
    if ! test -e $testScript
    then
        echo_error "Unknown test requested: $testId"
        echo "Expected to find it at $testScript"
        return 1;
    fi

    local log="$TMPDIR/$testId.log"

    echo "Running test: $testId"
    local result=undefined
    if $testRunner run $testScript > $log 2>&1
    then
        echo "Test $testId: OK"
        return 0;
    else
        result=$?
    fi

    # TODO: Report skipped tests and ignored failures more prominently. See
    # test-sources.sh for CHECK_OUTCOME_PHRASE tricks (but avoid duplication).
    echo
    echo_error "Test $testId: Failed with exit code $result"
    echo "::group::Test log tail:"
    tail -n 100 $log
    echo "::endgroup::"

    # TODO: Link to the artifact
    echo "See the test log (tailed above) for failure details: $log"
    return $result
}

check_pconn() {
    run_confirmed_test pconn
}

check_busy_restart() {
    run_confirmed_test busy-restart
}

check_proxy_collapsed_forwarding() {
    if ! has_commit_by_message 1af789e 'Do not stall if xactions overwrite a recently active'
    then
        echo "No proxy-collapsed-forwarding due to stalling transactions"
        return 0;
    fi
    run_confirmed_test proxy-collapsed-forwarding
}

check_proxy_update_headers_after_304() {
    if grep 'AC_INIT.*Proxy.,.[1234][.]' configure.ac
    then
        echo "No proxy-update-headers-after-304 until v5";
        return 0;
    fi
    run_confirmed_test proxy-update-headers-after-304
}

check_upgrade_protocols() {
    if ! grep -q http_upgrade_request_protocols src/cf.data.pre
    then
        echo "No upgrade-protocols without http_upgrade_request_protocols support";
        return 0;
    fi
    run_confirmed_test upgrade-protocols
}

check_truncated_responses() {
    run_confirmed_test truncated-responses
}

# executes a single check_name test named by the parameter
run_one_test() {
    local testName=$1

    # convert a test name foo into a check_foo() function name suffix; e.g.
    # busy-restart becomes busy_restart (to be called below as check_busy_restart)
    check=`echo $testName | sed s/-/_/g`

    check_$check
}

# executes all of the given tests, providing a summary of their failures
run_tests() {
    local result=0
    local failed_tests=""
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
        echo_error "Failed test(s):$failed_tests"
    fi
    return $result
}

# run the tests named on the command line (if any) or the default tests (otherwise)
main() {

    setup_test_tools || return

    local tests="$@"

    if test -z "$tests"
    then
        local default_tests="
            pconn
            proxy-update-headers-after-304
            upgrade-protocols
            proxy-collapsed-forwarding
            busy-restart
            truncated-responses
        "
        tests="$default_tests"
    fi

    run_tests $tests
}

main "$@"
exit $?
