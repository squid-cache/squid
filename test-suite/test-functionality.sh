#!/bin/sh

if test -z "$@"
then
    echo "usage: $0 <test-name-to-run> [test-parameters]"
    exit 1
fi

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

# run the command specified by the parameter
"$@"

