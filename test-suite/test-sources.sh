#!/bin/sh
#
## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This script checks source code compliance with a few Squid Project policies
# and recommendations. Some of the checks are applied to a subset of
# repository files, depending on the environment variables (first match wins):
# * If $PULL_REQUEST_NUMBER is set, checks sources modified by that Github PR;
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

# print an error message (with special markers recognized by Github Actions)
echo_error() {
    echo "::error ::" "$@"
}

# print a warning message (with special markers recognized by Github Actions)
echo_warning() {
    echo "::warning ::" "$@"
}

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

    # TODO: Remove this year 2020 workaround? Fresh master PRs should have Bug 5021 fix.
    if test -n "${PULL_REQUEST_NUMBER}"
    then
        # Detect stale PR branches that were forked before the first codespell
        # application and, hence, cannot be spellchecked without stepping on
        # misspellings in base code. Any PR-specific misspellings of stale
        # branches should be caught later, when testing the staged commit.
        required_title='Bug 5021: Spelling errors fixed by running scripts/spell-check.sh'
        if ! git log --grep "$required_title" "HEAD^1" | grep -q ^commit
        then
            echo "The base code of this PR does not support automated spelling checks."
            return 0;
        fi
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

    run $checker $copyrightOption no

    if run git diff --exit-code
    then
        return 0
    fi

    echo_error "Running $checker modifies sources"
    echo "The diff above details these modifications. Consider running $checker."
    # TODO: Require running source-maintenance.sh instead of ignoring this error.
    # TODO: Provide a downloadable patch that developers can apply.
    CHECK_OUTCOME_PHRASE="Ignored the need to run $checker"
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

if test -n "${PULL_REQUEST_NUMBER}"
then
    fetch_pr_refs || exit $?
fi
echo "Starting point: $STARTING_POINT (`git rev-parse $STARTING_POINT`)"

checks="$@"
if test -z "$checks"
then
    default_checks="
        diff
        spelling
        source-maintenance
    "
    checks="$default_checks"
fi

run_checks $checks
