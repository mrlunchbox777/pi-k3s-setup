# scripts adapted from https://medium.com/jit-team/building-a-gpu-enabled-kubernets-cluster-for-machine-learning-with-nvidia-jetson-nano-7b67de74172a
jetson-exec-command() {
  ssh ${username}@${hostname} -o "UserKnownHostsFile /tmp/known_hosts" -i "${id_rsa_pub_location}id_rsa" -p ${ssh_port} "$1"
}

jetsonDockerDaemonString="\
{
  “default-runtime”: “nvidia”,
  “runtimes”: {
    “nvidia”: {
      “path”: “nvidia-container-runtime”,
      “runtimeArgs”: []
    }
  }
}
"

jetson-update() {
  jetson-exec-command " \
    echo -e \"${password}\" | sudo -S systemctl set-default multi-user.target;
    echo -e \"${password}\" | sudo -S nvpmodel -m 0; \
    echo -e \"${password}\" | sudo -S swapoff -a; \
    echo \"$jetsonDockerDaemonString\" > /etc/docker/daemon.json; \
    echo -e \"${password}\" | sudo -S apt-get update; \
    echo -e \"${password}\" | sudo -S apt-get dist-upgrade; \
    echo -e \"${password}\" | sudo -S groupadd docker; \
    echo -e \"${password}\" | sudo -S usermod -aG docker ${username}; \
  "
}

jetson-reboot() {
  reboot
  wait_for_host
}

jetson-prep() {
  jetson-update
  jetson-reboot
}
