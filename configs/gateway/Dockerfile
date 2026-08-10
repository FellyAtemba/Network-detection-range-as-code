FROM alpine:3.20
RUN apk add --no-cache nftables iproute2 iproute2-tc tcpdump bash python3
COPY bootstrap.sh /bootstrap.sh
COPY nftables.conf /etc/nftables.conf
RUN chmod +x /bootstrap.sh
CMD ["/bootstrap.sh"]
