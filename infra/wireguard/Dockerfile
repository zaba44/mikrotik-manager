FROM alpine:3.20

RUN apk add --no-cache bash wireguard-tools iproute2 python3 iptables

COPY entrypoint.sh /entrypoint.sh
COPY agent.py /agent.py
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
