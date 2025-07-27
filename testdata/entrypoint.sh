#!/bin/sh

CONFIG_FILE=${1:-/etc/qssh/config.toml}

# Start SSH daemon in background
/usr/sbin/sshd

# Start nginx in background
nginx &

# Wait for services to start
sleep 3

/usr/local/bin/qssh-server -config-file "$CONFIG_FILE"
