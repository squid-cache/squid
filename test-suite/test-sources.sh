#!/bin/sh

# This script checks source code compliance with selected Squid Project
# policies and recommendations. Some of the checks are applied to a subset of
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

# XXX: A few of these helper functions are duplicated in test-functionality.sh

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

    local authorEmail=`git show --format="%ae" HEAD`;
    if test "$authorEmail" = 'squidadm@users.noreply.github.com'
    then
        echo "Ignoring 'git diff --check' failure for an automated commit";
        return 0;
    fi

    echo_error "git diff detected bad whitespace changes."
    echo "Please see 'git diff --check' output above for details."
    return 1;
}

check_spelling() {
    if ! test -e ./scripts/spell-check.sh
    then
        echo "This Squid version does not support automated spelling checks."
        return 0;
    fi

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

    # To reduce test timeouts due to slow codespell runs, we only check
    # modified files.
    local changed_files="`git diff --name-only ${STARTING_POINT}`"
    echo "changed files: $changed_files"
    if test -z "$changed_files"
    then
        echo "ERROR: Unable to determine which files have changed."
        return 1; # be conservative until we learn why that is a bad idea
    fi

    # TODO: Upgrade to codespell v2
    run sudo pip install \
        --ignore-installed \
        --no-cache-dir \
        --disable-pip-version-check \
        --quiet \
        --progress-bar off \
        codespell==1.16

    run ./scripts/spell-check.sh $changed_files

    if run git diff --word-diff --exit-code
    then
        return 0;
    fi

    echo_error "Spelling mistakes detected."
    echo "The log above ends with a word diff showing suggested fixes."
    echo "Please adjust scripts/codespell-whitelist.txt or fix spelling."

    # Detect code that does not contain the second out-of-band spelling fix.
    # TODO: Remove this workaround check after 2022-03-02 or so.
    if ! has_commit_by_message 7c25db3 'Maintenance: Fix two misspellings'
    then
        echo "The diff might include old misspellings in the official code"
        echo "that were fixed by the above commit. Ignore those misspellings."
        return 0;
    fi

    return 1;
}

check_source_maintenance() {
    checker=./scripts/source-maintenance.sh
    copyrightOption='--check-and-update-copyright'
    if ! fgrep -q -e $copyrightOption $checker
    then
        echo_warning "Skipping $checker checks because $checker does not support $copyrightOption"
        return 0;
    fi

    # The OS may not provide the right version of the astyle package, but
    # source formatting (by developers) is not yet enforced, so we run with
    # whatever astyle is provided, abusing the fact that $checker skips
    # formatting iff it can execute a binary called astyle but does not like
    # astyle's version.

    # TODO: Require successful gperf generation;
    # bootstrap/configure sources to test: make -C src/http gperf-files

    # TODO: Check whether this workaround is no longer necessary.
    touch boilerplate_fix.sed

    run $checker $copyrightOption no

    if run git diff --exit-code
    then
        return 0
    fi

    echo_error "Squid $checker modified sources as shown in the diff above."
    echo "Please consider (carefully) applying $checker before merging."
    # TODO: Require running source-maintenance.sh instead of ignoring this error.
    # TODO: Provide a downloadable patch that developers can apply.
    return 0
}

run_one_check() {
    checkName=$1

    # convert a check name foo into a check_foo() function name
    # e.g. busy-restart becomes check_busy_restart
    check=`echo $checkName | sed s/-/_/g`

    echo "::group::Check $checkName"
    local result=undefined
    check_$check
    result=$?
    echo "::endgroup::"

    if test "$result" -eq 0
    then
        echo "Check $checkName: OK"
    else
        echo_error "Check $checkName: Failed with exit code $result:"
    fi

    return $result
}

run_checks() {
    result=0
    failed_checks=""
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
