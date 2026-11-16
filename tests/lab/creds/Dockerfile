FROM golang:1.22-alpine AS kerbrute
RUN apk add --no-cache git \
 && GOBIN=/out/master go install github.com/ropnop/kerbrute@9cfb81e4fab8037acb44c678773ca3f93bc2b39c \
 && GOBIN=/out/v1.0.3 go install github.com/ropnop/kerbrute@v1.0.3

FROM alpine:3.20 AS build
RUN apk add --no-cache build-base linux-headers git openssl-dev zlib-dev libssh-dev pcre2-dev
RUN git init /src/john && cd /src/john \
 && git fetch --depth 1 https://github.com/openwall/john 37bebbe4b6442c8dd3888e5848ef062c0783e9f3 \
 && git checkout -q FETCH_HEAD && cd src && ./configure --disable-native-tests && make -sj4
RUN git init /src/hydra && cd /src/hydra \
 && git fetch --depth 1 https://github.com/vanhauser-thc/thc-hydra 707c822e88938c526279fcabc10a8a265bbc53c4 \
 && git checkout -q FETCH_HEAD && ./configure --prefix=/usr/local && make -j4 && make install

FROM alpine:3.20
RUN apk add --no-cache openssl zlib libssh pcre2 libgomp samba-client python3 git \
 && python3 -m venv /opt/impacket \
 && /opt/impacket/bin/pip install --no-cache-dir \
        git+https://github.com/fortra/impacket@75938fcb0145b476250940d740f71394676288cb \
 && apk del git
COPY --from=build /src/john/run /opt/john
COPY --from=build /usr/local/bin/hydra /usr/local/bin/hydra
COPY --from=kerbrute /out/master/kerbrute /usr/local/bin/kerbrute
COPY --from=kerbrute /out/v1.0.3/kerbrute /usr/local/bin/kerbrute-1.0.3
RUN printf '#!/bin/sh\nexec /opt/john/john "$@"\n' > /usr/local/bin/john && chmod +x /usr/local/bin/john
ENV PATH=/opt/impacket/bin:$PATH
