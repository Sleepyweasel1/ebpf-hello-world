#!/usr/bin/env bash
#MISE description="mount tracefs and debugfs for BPF tracing"
mkdir -p /sys/kernel/tracing /sys/kernel/debug
mount -t tracefs tracefs /sys/kernel/tracing
mount -t debugfs debugfs /sys/kernel/debug
grep -E "tracefs|debugfs" /proc/mounts