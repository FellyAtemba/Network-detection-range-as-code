FROM alpine:3.20
RUN apk add --no-cache iproute2 curl netcat-openbsd bind-tools python3 bash tcpdump
COPY server_daemons.py /opt/server_daemons.py
CMD ["python3", "/opt/server_daemons.py"]
