#!/bin/bash
set -e

echo ==1==
cat <<EOF | nc 127.0.0.1 8080
bad request

EOF

echo ==2==
cat <<EOF | nc 127.0.0.1 8080
GET http://localhost:8081/hello HTTP/1.1
Host: localhost:8081

EOF

# echo ==3==
# cat <<EOF | nc 127.0.0.1 8080
# POST http://localhost:8081/ HTTP/1.1
# Host: localhost:8081
# Content-Length: 18
# Client-Header: Value

# hello from client
# EOF

echo ==4==
cat <<EOF | nc 127.0.0.1 8080
CONNECT localhost:8081 HTTP/1.1
Host: localhost:8081

input-data
EOF

echo ==5==
cat <<EOF | nc 127.0.0.1 8080
CONNECT localhost:8082 HTTP/1.1
Host: localhost:8082

EOF

echo ==6==
cat <<EOF | nc 127.0.0.1 8080
GET http://localhost:8081/chunked HTTP/1.1
Host: localhost:8081

EOF

# echo ==?==
# cat <<EOF | nc --no-shutdown 127.0.0.1 8080
# GET http://10.0.2.2:8081/hello HTTP/1.1
# Host: 10.0.2.2:8081

# EOF
