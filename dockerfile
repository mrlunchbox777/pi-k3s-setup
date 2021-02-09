FROM bash:5

SHELL ["/usr/local/bin/bash", "-c"]
CMD bash /runme.sh
WORKDIR /
RUN apk add --no-cache bind-tools openssh sshpass
COPY runme.sh ssh_give_pass.sh /
RUN chmod +x runme.sh ssh_give_pass.sh
