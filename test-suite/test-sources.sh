#!/bin/sh
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This script checks source code compliance with a few Squid Project policies
# and recommendations. Some of the checks are applied to a subset of
# repository files, depending on the environment variables (first match wins):
# * If $PULL_REQUEST_NUMBER is set, checks sources modified by that GitHub PR;
# * If $FORK_POINT is set, checks sources modified since that commit;
# * Otherwise, checks sources modified since the parent commit (HEAD^).
STARTING_POINT="HEAD^"
if test -n "${PULL_REQUEST_NUMBER}"
then
    STARTING_POINT="refs/pull/${PULL_REQUEST_NUMBER}/merge^1"
elif test -n "${FORK_POINT}"
then
    STARTING_POINT="${FORK_POINT}"
fi

# Customizable check outcome description logged by run_one_check()
CHECK_OUTCOME_PHRASE=""

# XXX: echo_*() and run() functions are duplicated in test-functionality.sh.

# print an error message (with special markers recognized by GitHub Actions)
echo_error() {
    echo "::error ::" "$@"
}

# print a warning message (with special markers recognized by GitHub Actions)
echo_warning() {
    echo "::warning ::" "$@"
}

# print and execute the given command
run() {
    echo "running: $@"
    "$@"
}

# Get key pull request commits to be able to diff against them, avoiding:
# 'refs/pull/167/merge^1': unknown revision or path not in the working tree
fetch_pr_refs() {
    # TODO: There may be a simpler way to get the necessary commits via GitHub
    # Actions contexts: github.event.pull_request.base.sha and github.sha.

    # quiet "adding host key" warnings
    export GIT_SSH_COMMAND="ssh -o LogLevel=ERROR"
    run git fetch --force --quiet origin \
        "refs/pull/${PULL_REQUEST_NUMBER}/merge:refs/pull/${PULL_REQUEST_NUMBER}/merge" \
        "refs/pull/${PULL_REQUEST_NUMBER}/head:refs/pull/${PULL_REQUEST_NUMBER}/head";
}

# check changed lines for conflict markers or whitespace errors
check_diff() {
    if run git -c core.whitespace=-blank-at-eof diff --check ${STARTING_POINT}
    then
        return 0;
    fi

    local authorEmail="`git show --format="%ae" HEAD`";
    if test "$authorEmail" = 'squidadm@users.noreply.github.com'
    then
        CHECK_OUTCOME_PHRASE="Ignored 'git diff --check' failure for an automated commit";
        return 0;
    fi

    echo_error "git diff detected bad whitespace changes."
    echo "Please see 'git diff --check' output above for details."
    return 1;
}

# check changed files for certain misspelled words
check_spelling() {
    if ! test -e ./scripts/spell-check.sh
    then
        CHECK_OUTCOME_PHRASE="Skipped because this Squid version is missing support for spelling checks."
        return 0;
    fi

    if ! git diff --quiet
    then
        CHECK_OUTCOME_PHRASE="Skipped due to a dirty working directory"
        return 0;
    fi

    # To avoid flagging out-of-scope misspellings, only check modified files.
    # This also speeds up tests and helps avoid slow-codespell timeouts.
    local changed_files="`git diff --name-only ${STARTING_POINT}`"
    if test -z "$changed_files"
    then
        echo "ERROR: Unable to determine which files have changed."
        return 1; # be conservative until we learn why that is a bad idea
    fi
    echo "changed files: $changed_files"

    run ./scripts/spell-check.sh $changed_files

    if run git diff --word-diff --exit-code
    then
        return 0;
    fi

    echo_error "Spelling mistakes detected."
    echo "The log above ends with a word diff showing suggested fixes."
    echo "Please adjust scripts/codespell-whitelist.txt or fix spelling."

    return 1;
}

# check for certain problems fixed by a ./scripts/source-maintenance.sh
check_source_maintenance() {
    if ! git diff --quiet
    then
        CHECK_OUTCOME_PHRASE="Skipped due to a dirty working directory"
        return 0;
    fi

    local checker=./scripts/source-maintenance.sh

    local copyrightOption='--check-and-update-copyright'
    if ! grep -q -e $copyrightOption $checker
    then
        echo_warning "Skipping $checker checks because $checker does not support $copyrightOption"
        CHECK_OUTCOME_PHRASE="Skipped due to missing $copyrightOption support"
        return 0;
    fi

    # The OS may not provide the right version of the astyle package, but
    # source formatting (by developers) is not yet enforced, so we run with
    # whatever astyle is provided, abusing the fact that $checker skips
    # formatting iff it can execute a binary called astyle but does not like
    # astyle's version.

    # Avoid distracting $checker warnings; TODO: Fix $checker instead.
    touch boilerplate_fix.sed

    if ! run $checker $copyrightOption no
    then
        echo_error "Running $checker modified sources"
        CHECK_OUTCOME_PHRASE="Ignored $checker failure" # maybe overwritten below
        # TODO: Require source-maintenance.sh application instead of ignoring this error.
    fi

    if run git diff --exit-code
    then
        return 0
    fi

    echo_error "Running $checker modified sources"
    echo "The diff above details these modifications. Consider running $checker."
    # TODO: Provide a downloadable patch that developers can apply.
    CHECK_OUTCOME_PHRASE="Ignored the need to run $checker"
    # TODO: Require source-maintenance.sh application instead of ignoring these changes.
    return 0
}

run_one_check() {
    local checkName=$1

    # convert a check name foo into a check_foo() function name
    # e.g. busy-restart becomes check_busy_restart
    local check=`echo $checkName | sed s/-/_/g`

    CHECK_OUTCOME_PHRASE=""

    echo "::group::Check $checkName"
    local result=undefined
    check_$check
    result=$?

    if test "$result" -eq 0
    then
        if test -n "$CHECK_OUTCOME_PHRASE"
        then
            echo "::endgroup::"
            # place this custom outcome outside of the check group so that it
            # remains visible in the default/unexpanded Actions job log
            echo_warning "Check $checkName: $CHECK_OUTCOME_PHRASE"
        else
            echo "Check $checkName: OK"
            echo "::endgroup::"
        fi
    else
        echo "Check exit code: $result"
        echo "::endgroup::"
        # place this error message outside of the check group so that it
        # remains visible in the default/unexpanded Actions job log
        echo_error "Check $checkName: ${CHECK_OUTCOME_PHRASE:-Failure}"
    fi

    return $result
}

# executes all of the given checks, providing a summary of their failures
run_checks() {
    local result=0
    local failed_checks=""

    for checkName in "$@"
    do
        if run_one_check $checkName
        then
            continue;
        else
            result=$?
            failed_checks="$failed_checks $checkName"
        fi
    done

    if test -n "$failed_checks"
    then
        echo_error "Failed check(s):$failed_checks"
    fi
    return $result
}

# run the checks named on the command line (if any) or the default checks (otherwise)
main() {

    if test -n "${PULL_REQUEST_NUMBER}"
    then
        fetch_pr_refs || return
    fi
    echo "Starting point: $STARTING_POINT (`git rev-parse $STARTING_POINT`)"

    local checks="$@"

    if test -z "$checks"
    then
        local default_checks="
            diff
            spelling
            source-maintenance
        "
        checks="$default_checks"
    fi

    run_checks $checks
}

main "$@"
exit $?
