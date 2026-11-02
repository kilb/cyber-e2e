#!/bin/sh
set -e
mkdir -p .rrg-build/bin
cc -O0 -g -fsanitize=address -fno-omit-frame-pointer -o .rrg-build/bin/prog prog.c
