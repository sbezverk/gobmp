#!/bin/sh
set -e

# GRPC port check
grpc_port="$VAR_GRPC_PORT"
if [ ! -z "${grpc_port}" ];then
    nc -z 0.0.0.0 "${grpc_port}" 2>&1
fi
# BGP port check
nc -z 0.0.0.0 179 2>&1