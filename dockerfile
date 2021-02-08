FROM bash:5

CMD bash /runme.sh
WORKDIR /
RUN apk add bind-tools
COPY runme.sh ssh_give_pass.sh /
RUN chmod +x runme.sh ssh_give_pass.sh
