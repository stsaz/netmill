FROM alpine:3.18
COPY ./netmill-0/  /netmill-0/
ENTRYPOINT [ "/netmill-0/netmill" ]
EXPOSE 53/udp 80
