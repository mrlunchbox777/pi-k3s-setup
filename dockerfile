FROM bash:5

SHELL ["/usr/local/bin/bash", "-c"]
CMD bash /runme.sh
WORKDIR /

RUN apk add --no-cache --update bind-tools openssh sshpass curl netcat-openbsd openssl && \
    rm -rf /var/cache/apk/*
RUN curl -sLS https://get.k3sup.dev | sh
COPY runme.sh /
RUN chmod +x runme.sh && \
    mkdir -p lib
COPY lib/* lib/
RUN chmod -R +x lib/
