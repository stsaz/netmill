#!/bin/bash
set -e

#1
cat <<EOF | nc -l 127.0.0.1 8080
HTTP/1.1 200 OK
Content-Length: 0

EOF

#2
cat <<EOF | nc -l 127.0.0.1 8080
HTTP/1.1 200 OK
Content-Length: 6

hello
EOF

#3
cat <<EOF | nc -l 127.0.0.1 8080
HTTP/1.1 200 OK
Transfer-Encoding: chunked

2
he
3
llo
0

EOF

#4
cat <<EOF | nc -l 127.0.0.1 8080
HTTP/1.1 500 Error
Content-Length: 6

error
EOF

#5
cat <<EOF | nc -l 127.0.0.1 8080
output-data
EOF

#6
cat <<EOF | nc -l 127.0.0.1 8080
HTTP/1.1 200 OK


EOF

#7
cat <<EOF | nc -l 127.0.0.1 8080
HTTP/1.1 302 Found
Location: http://localhost:8080/redirect
Content-Length: 9

/redirect
EOF
cat <<EOF | nc -l 127.0.0.1 8080
HTTP/1.1 200 OK
Content-Length: 20

redirect successful
EOF
