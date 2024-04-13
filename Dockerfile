FROM alpine:3.18
COPY ./netmill-0/  /netmill-0/
ENTRYPOINT [ "/netmill-0/netmill" ]
