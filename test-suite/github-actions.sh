#!/bin/sh

# XXX: https://dev.to/scienta/get-changed-files-in-github-actions-1p36
# ${{ github.event.pull_request.base.sha }} ${{ github.sha }}

if test -z "$@"
then
    echo "usage: $0 <test-name-to-run> [test-parameters]"
    exit 1
fi

# This script requires $PULL_REQUEST_NUMBER for testing PR commits

run_() {
    echo "running: $@"
    "$@"
}

fetch_pr_refs_() {
    # quiet "adding host key" warnings
    export GIT_SSH_COMMAND="ssh -o LogLevel=ERROR"
    run_ git fetch --force --quiet origin \
        "refs/pull/${PULL_REQUEST_NUMBER}/merge:refs/pull/${PULL_REQUEST_NUMBER}/merge" \
        "refs/pull/${PULL_REQUEST_NUMBER}/head:refs/pull/${PULL_REQUEST_NUMBER}/head";
}

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

build_and_install_for_functionality_checks() {
    ./bootstrap.sh
    ./configure --with-openssl
    make -j4
    sudo make install
    sudo chown -R nobody:nogroup /usr/local/squid
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

check_diff() {
    if test -n "${PULL_REQUEST_NUMBER}";
    then
        fetch_pr_refs_
        target="refs/pull/${PULL_REQUEST_NUMBER}/merge^1"
        pr="refs/pull/${PULL_REQUEST_NUMBER}/head"
        if run_ git -c core.whitespace=-blank-at-eof diff --check ${target}...${pr}
        then
            return 0;
        fi

        authorEmail=`git show --format="%ae" refs/pull/${PULL_REQUEST_NUMBER}/merge`;
        if test "$authorEmail" = 'squidadm@users.noreply.github.com'
        then
            echo "Ignoring 'git diff --check' failure for an automated commit";
            return 0;
        fi

        echo "PR may contain bad whitespace changes."
        echo "Please see 'git diff --check' output above for details."
        return 1;
    fi
}

check_spelling() {
    if ! test -e ./scripts/spell-check.sh
    then
        echo "This Squid version does not support automated spelling checks."
        return 0;
    fi

    if test -n "${PULL_REQUEST_NUMBER}"
    then
        # For PR branches, we checkout the last PR commit. $changed_files will
        # compare it with the anticipated (by GitHub) target master commit.
        fetch_pr_refs_
        run_ git checkout --quiet refs/pull/${PULL_REQUEST_NUMBER}/head
        target="refs/pull/${PULL_REQUEST_NUMBER}/merge^1"

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
    else
        target="HEAD^1"
    fi

    # To reduce test timeouts due to slow codespell runs, we only check
    # modified files.
    changed_files=`git diff --name-only "$target"`
    echo "changed files: $changed_files"
    if test -z "$changed_files"
    then
        echo "ERROR: Unable to determine which files have changed."
        return 1; # be conservative until we learn why that is a bad idea
    fi

    run_ sudo pip install \
        --ignore-installed \
        --no-cache-dir \
        --disable-pip-version-check \
        --quiet \
        --progress-bar off \
        codespell==1.16

    run_ ./scripts/spell-check.sh $changed_files

    if run_ git diff --word-diff --exit-code
    then
        return 0;
    fi

    echo "Spelling mistakes detected."
    echo "The log above ends with a word diff showing suggested fixes."
    echo "Please adjust scripts/codespell-whitelist.txt or fix spelling."

    # Detect code that does not contain the second out-of-band spelling fix.
    # TODO: Remove this workaround check after 2022-03-02 or so.
    if ! has_commit_by_message_ 7c25db3 'Maintenance: Fix two misspellings'
    then
        echo "The diff might include old misspellings in the official code"
        echo "that were fixed by the above commit. Ignore those misspellings."
        return 0;
    fi

    return 1;
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

    local runner=extras/daft/src/cli/daft.js
    local testScript=extras/squid-dafts/tests/$testId.js

    if ! test -e $testScript
    then
        echo "Unknown test requested: $testId"
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
    echo "Test $testId: Failed with exit code $result:"
    tail -n 100 $testId.log
    # TODO: Link to the artifact
    echo "Test $testId failed. See $testId.log for failure details."
    return $result
}

check_pconn() {
    run_daft_test_ pconn
}

check_busy_restart() {
    run_daft_test_ busy-restart
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

check_source_maintenance() {
    checker=./scripts/source-maintenance.sh
    copyrightOption='--check-and-update-copyright'
    if ! fgrep -q -e $copyrightOption $checker
    then
        echo "Skipping $checker checks because $checker does not support $copyrightOption"
        return 0;
    fi

    # The build OS may not provide the right version of the astyle package,
    # but source formatting (by developers) is not yet enforced anyway, so we
    # run with whatever astyle is provided, abusing the fact that $checker
    # skips formatting iff it can execute a binary called astyle but does not
    # like astyle's version.

    # TODO: Require successful gperf generation;
    # bootstrap/configure sources to test: make -C src/http gperf-files

    touch boilerplate_fix.sed

    run_ $checker $copyrightOption no

    if run_ git diff --exit-code
    then
        return 1; # XXX 0!
    fi

    echo "Squid $checker modified sources as shown in the diff above."
    echo "Please consider (carefully) applying $checker before merging."
    return 1;
}

# run the command specified by the parameter
"$@"

