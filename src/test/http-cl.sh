#!/bin/bash
set -e

#1
cat <<EOF | nc 127.0.0.1 8080
GET / HTTP/1.1
Host: localhost:8080

EOF

#2
cat <<EOF | nc 127.0.0.1 8080
GET /404 HTTP/1.1
Host: localhost:8080

EOF

#3
cat <<EOF | nc 127.0.0.1 8080
GET /1 HTTP/1.1
Host: localhost:8080

GET /2 HTTP/1.1
Host: localhost:8080

EOF
