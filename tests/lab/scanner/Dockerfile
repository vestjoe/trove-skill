FROM alpine:3.20

ARG TARGETARCH
ARG MASSCAN_VERSION=1.3.2
ARG NAABU_VERSION=2.7.0
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_TEMPLATES_VERSION=v10.5.0

RUN apk add --no-cache libpcap libpcap-dev nmap nmap-scripts bind-tools ca-certificates \
 && apk add --no-cache --virtual .build build-base linux-headers git curl unzip \
 && git clone --depth 1 --branch "$MASSCAN_VERSION" https://github.com/robertdavidgraham/masscan /tmp/masscan \
 && make -C /tmp/masscan -j4 && install /tmp/masscan/bin/masscan /usr/local/bin/masscan \
 && curl -fsSL -o /tmp/naabu.zip \
        "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${TARGETARCH}_musl.zip" \
 && unzip -o /tmp/naabu.zip naabu -d /usr/local/bin \
 && curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
 && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin \
 && git clone --depth 1 --branch "$NUCLEI_TEMPLATES_VERSION" https://github.com/projectdiscovery/nuclei-templates /opt/nuclei-templates \
 && rm -rf /tmp/masscan /tmp/naabu.zip /tmp/nuclei.zip /opt/nuclei-templates/.git && apk del .build
