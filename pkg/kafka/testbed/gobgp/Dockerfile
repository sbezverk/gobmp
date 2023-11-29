FROM alpine:3.16.3

ARG GOBGP_VERSION=3.20.0

RUN wget -q https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz && \
    tar -xzvf gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz && \
    mv gobgp gobgpd /usr/bin && \
    mkdir /etc/gobgp && \
    rm -f gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz && \
    apk add --no-cache bind-tools ipcalc && \
    rm -rf /var/cache/apk/*

COPY scripts/hc.sh /tmp/hc.sh
COPY scripts/init.sh /init.sh

WORKDIR /

RUN apk add --no-cache kcat

ENTRYPOINT [ "/bin/sh" ]
CMD [ "/init.sh" ]