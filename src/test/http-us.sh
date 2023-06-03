#!/bin/bash
set -e

echo ==2==
cat <<EOF | nc -l 127.0.0.1 8081
HTTP/1.1 200 OK From Upstream
Server: upstream
Content-Length: 20
Upstream-Header: Value

hello from upstream
EOF

echo ==4==
cat <<EOF | nc -l 127.0.0.1 8081
output-data
EOF

echo ==6==
cat <<EOF | nc -l 127.0.0.1 8081
HTTP/1.1 200 OK
Transfer-Encoding: chunked

2
he
3
llo
0

EOF
