#!/bin/sh

CONFIG_FILE=${1:-/etc/qssh/config.toml}
/usr/sbin/sshd

sleep 2

/usr/local/bin/qssh-server -config-file "$CONFIG_FILE"
