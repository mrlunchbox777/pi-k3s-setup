FROM bash:5

SHELL ["/usr/local/bin/bash", "-c"]
CMD bash /runme.sh
WORKDIR /

RUN apk add --no-cache bind-tools openssh sshpass curl
RUN curl -sLS https://get.k3sup.dev | sh; \
    ls
#   cp k3sup /usr/local/bin
COPY runme.sh ssh_give_pass.sh /
RUN chmod +x runme.sh ssh_give_pass.sh
