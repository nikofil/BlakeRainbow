#!/bin/bash
dbus-monitor | stdbuf -o0 grep -Eo "[0-9a-f]{64}" | ./a.out