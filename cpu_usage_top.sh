#!/bin/bash
PNAME="$1"
LOG_FILE="$2"
PID=$(pidof ${PNAME})
top -b -d 0.01 -p $PID | awk \
    -v cpuLog="$LOG_FILE" -v pid="$PID" -v pname="$PNAME" '
    /^top -/{time = $3}
    $1+0>0 {printf "%d%%\n", \
            $9 > cpuLog
            fflush(cpuLog)}'
