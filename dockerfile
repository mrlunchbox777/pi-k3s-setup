FROM bash:5

SHELL ["/usr/local/bin/bash", "-c"]
CMD bash /runme.sh
WORKDIR /

RUN apk add --no-cache bind-tools openssh sshpass curl netcat-openbsd
RUN curl -sLS https://get.k3sup.dev | sh
COPY runme.sh ssh_give_pass.sh myserver.cnf /
RUN chmod +x runme.sh ssh_give_pass.sh
