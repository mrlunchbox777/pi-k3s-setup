install_k3sup_host() {
  write_block 2 "Installing k3sup if needed"
  if [ -z /usr/local/bin/k3sup ]; then
    write_block 2 "Installing k3sup"
    curl -sLS https://get.k3sup.dev | sh
    most_recent_command_value=$?
    check_for_error $most_recent_command_value "target setup" "downloading k3sup"
  fi
}

check_for_running_k3s() {
  ssh -i "${id_rsa_pub_location}id_rsa" -o "UserKnownHostsFile /tmp/known_hosts" "${username}"@${hostname} -p ${ssh_port} " \
    systemctl is-active --quiet k3s || exit 1
  "
  most_recent_command_value=$?
  write_block 1 "Just checked for running k3s, if it errors here, k3s failed to start up. " \
    "On the target - See \"systemctl status k3s.service\" and \"journalctl -xe\" for details." \
    "Check the logs up above as well."
  check_for_error $most_recent_command_value "target setup" "check for running k3s"
}

run_k3sup() {
  # TODO: extra output here
  write_block 2 "k3sup install node"
  if [ ! -z "${cluster_server_name}" ]; then
    server_string=""
    if [ ${join_as_server} -gt 0 ]; then
      server_string="--server"
      write_block 2 "k3sup join as server"
    else
      write_block 2 "k3sup don't join as server"
    fi
    k3sup join --host ${hostname} --user ${username} --server-host ${cluster_server_name} --server-user ${cluster_username} --ssh-key "${keyname}" ${server_string} --server-ssh-port ${cluster_ssh_port} --ssh-port ${ssh_port}
    most_recent_command_value=$?
    if [ $1 -eq 1 ]; then
      check_for_error $most_recent_command_value "target setup" "k3sup join"
    else
      return 1
    fi
  else
    cluster_string=""
    if [ ${install_as_cluster} -gt 0 ]; then
      cluster_string="--cluster"
      write_block 2 "k3sup install as cluster"
    else
      write_block 2 "k3sup don't install as cluster"
    fi
    k3sup install --host ${hostname} --user ${username} --ssh-key "${keyname}" ${cluster_string} --local-path "./kubeconfig/kubeconfig" --ssh-port ${ssh_port} --context "${context_name}"
    most_recent_command_value=$?
    if [ $1 -eq 1 ]; then
      check_for_error $most_recent_command_value "target setup" "k3sup install"
    else
      return 1
    fi
  fi
  check_for_running_k3s
}
