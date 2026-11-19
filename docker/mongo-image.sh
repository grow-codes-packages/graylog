#!/bin/sh
# Prints the MongoDB image for the Docker fixture when this host needs a non-catalog one.
#
# MongoDB 8.x crashes on Linux kernels 6.19 to 7.0.13 (SERVER-121912, TCMalloc vs the rseq ABI):
# mongo:8.2.3-noble segfaults about 30 s after start, newer 8.0 patches refuse to start. Graylog
# 7.0 supports MongoDB 7.0 to 8.2, so such hosts use MongoDB 7.0. Prints nothing otherwise, and
# docker/compose.service.yml keeps the catalog image (mongo:8.2.3-noble).
set -u
v=$(uname -r)
maj=${v%%.*}
v=${v#*.}
min=${v%%.*}
v=${v#*.}
pat=${v%%[!0-9]*}
pat=${pat:-0}
if { [ "$maj" -eq 6 ] && [ "$min" -ge 19 ]; } ||
  { [ "$maj" -eq 7 ] && [ "$min" -eq 0 ] && [ "$pat" -lt 14 ]; }; then
  echo "mongo:7.0.48-jammy"
fi
