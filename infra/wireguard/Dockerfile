FROM alpine:3.20

RUN apk add --no-cache bash wireguard-tools iproute2 python3 iptables

COPY entrypoint.sh /entrypoint.sh
COPY agent.py /agent.py
RUN chmod +x /entrypoint.sh

# Wersja wbudowana przy budowaniu (release.yml); obraz zbudowany recznie ma `dev`.
ARG MTM_BUILD_VERSION=dev
ARG MTM_BUILD_COMMIT=
ARG MTM_BUILD_DATE=
ENV MTM_BUILD_VERSION=$MTM_BUILD_VERSION MTM_BUILD_COMMIT=$MTM_BUILD_COMMIT MTM_BUILD_DATE=$MTM_BUILD_DATE

ENTRYPOINT ["/entrypoint.sh"]
