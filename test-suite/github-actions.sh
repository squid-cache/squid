#!/bin/sh

# XXX: https://dev.to/scienta/get-changed-files-in-github-actions-1p36
# ${{ github.event.pull_request.base.sha }} ${{ github.sha }}

# Empty for commits not triggered by opening of a pull request
echo "PULL_REQUEST_NUMBER=${PULL_REQUEST_NUMBER}"

if test -z "$@"
then
    echo "usage: $0 <test-name-to-run> [test-parameters]"
    exit 1
fi

# XXX: Trailing whitespace on this line      

run_() {
    echo "running: $@"
    "$@"
}

install_package_() {
    pkg="$1"
    run_ install-package $pkg > /dev/null
    apt list --installed $pkg
}

show_log() {
    log=$1
    if test -e $log;
    then
        echo "Log: $log";
        ls -l $log
        cat $log;
    fi
}

# TODO: Remove when unused
showLog() {
    show_log "$@"
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

# meant to be executed in the "Setup" job
setup() {
    # Semaphore CI is running Ubuntu 14.04 which has a problem with Let's Encrypt
    # that manifests in bogus "Issued certificate has expired" errors. Based on
    # https://askubuntu.com/questions/1366704/how-to-install-latest-ca-certificates-on-ubuntu-14#comment2352285_1366719
    sudo sed -i 's|mozilla/DST_Root_CA_X3.crt|!mozilla//DST_Root_CA_X3.crt|g' /etc/ca-certificates.conf
    sudo dpkg-reconfigure -fnoninteractive ca-certificates

    install_package_ ed
    install_package_ libcppunit-dev
}

build_and_install_for_functionality_checks() {
    ./bootstrap.sh
    ./configure --with-openssl
    make -j4
    sudo make install
    sudo chown -R nobody:nogroup /usr/local/squid
}

check_client_certificate_handling() {
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

        echo "PR contains bad whitespace changes."
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

check_basic_functionality() {
    # decide which tests to run
    tests="pconn"
    tests="$tests busy-restart";

    if has_commit_by_message_ 1af789e 'Do not stall if xactions overwrite a recently active'
    then
        tests="$tests proxy-collapsed-forwarding";
    else
        echo "No proxy-collapsed-forwarding due to stalling transactions"
    fi

    if egrep 'AC_INIT.*Proxy.,.[1234][.]' configure.ac
    then
        echo "No proxy-update-headers-after-304 until v5";
    else
        tests="$tests proxy-update-headers-after-304";
    fi

    if fgrep -q http_upgrade_request_protocols src/cf.data.pre
    then
        tests="$tests upgrade-protocols";
    else
        echo "No upgrade-protocols without http_upgrade_request_protocols support";
    fi

    export DAFT_TESTS="$tests"

    local url=https://github.com/measurement-factory/squid-overlord/raw/stable2/overlord.pl
    curl -sSL $url | sudo -n --background -u nobody perl - > ~/squid-overlord.log 2>&1

    echo "Test plan: $DAFT_TESTS"

    testIds=`echo "$DAFT_TESTS" | sed 's/[^-a-zA-Z0-9 ]//g'`
    if test "$testIds" != "$DAFT_TESTS"
    then
        echo "Bad test plan."
        return 1;
    fi

    result=0
    runner=/opt/daft/stable/src/cli/daft.js # XXX: Fetch Daft and squid-dafts!
    for testId in $testIds
    do
        testScript=/opt/daft/stable/tests/$testId.js

        if ! test -e $testScript
        then
            echo "Skipping unknown planned test: $testId"
            result=1
            continue;
        fi

        if $runner run $testScript > $testId.log 2>&1
        then
            echo "Test $testId: OK"
        else
            result=$?
            echo
            echo "Test $testId: Failed with exit code $result:"
            cat $testId.log
            echo "Test $testId failed. See the test log above for failure details."
            return $result
        fi
    done

    if test $result = 0
    then
        echo "All tests passed."
    else
        echo "Some tests were skipped."
    fi
    return $result;
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
    install_package_ astyle

    # TODO: Require successful gperf generation, install gperf, and then
    # bootstrap/configure sources to test: make -C src/http gperf-files

    touch boilerplate_fix.sed

    run_ $checker $copyrightOption no

    if ! run_ git diff --exit-code
    then
        echo "Squid $checker modified sources as shown in the diff above."
        echo "Please consider (carefully) applying $checker before merging."
        # TODO: Insist on developers formatting their sources by returning 1.
        return 0;
    fi
    return 0;
}

show_artifacts() {
    show_log /usr/local/squid/var/logs/overlord/squid.out
    show_log ~/squid-overlord.log
}

# meant to be executed in the "After job" job
after_job() {
    show_artifacts
}

# run the command specified by the parameter
"$@"

