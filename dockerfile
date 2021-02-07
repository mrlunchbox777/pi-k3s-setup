FROM alpine:3.12

CMD runme.sh
WORKDIR /
COPY runme.sh ssh_give_pass.sh /