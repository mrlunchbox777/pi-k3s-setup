first_command_run() {
  password_to_use=""
  if [ $always_use_key -gt 0 ]; then
    password_to_use="${password}"
  else
    password_to_use="${initial_target_password}"
  fi
  execString=" \
    getent passwd ${username} > /dev/null 2&>1; \
    if [ ! \$? -eq 0 ]; then \
      echo -e \"${password_to_use}\" | sudo -S sh -c \" \
        echo -e \"${password_to_use}\" | sudo -S useradd -m -G sudo ${username}; \
        echo \\\"${username}:${password}\\\" | chpasswd; \
      \"; \
    fi; \
    if [[ ! \"${initial_target_hostname}\" == \"${hostname}\" ]]; then \
      echo \"${hostname}\" > /tmp/basic-setup-new-hostname ; \
      echo -e \"${password_to_use}\" | sudo -S mv -f /tmp/basic-setup-new-hostname /etc/hostname; \
    fi; \
    if [ ${skip_deny_ssh_passwords} -eq 0 ]; then \
      echo -e \"${password_to_use}\" | sudo -S sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config; \
    fi; \
    echo -e \"${password_to_use}\" | sudo -S chown ${username}:$username /tmp/id_rsa.pub; \
    echo -e \"${password_to_use}\" | sudo -S chmod 600 /tmp/id_rsa.pub; \
    echo -e \"${password_to_use}\" | sudo -S -u ${username} mkdir -p \"/home/${username}/.ssh/\"; \
    echo -e \"${password_to_use}\" | sudo -S chown ${username}:$username \"/home/${username}/.ssh/\"; \
    echo -e \"${password_to_use}\" | sudo -S chmod 700 \"/home/${username}/.ssh/\"; \
    echo -e \"${password_to_use}\" | sudo -S -u ${username} sh -c 'cat /tmp/id_rsa.pub >> \"/home/${username}/.ssh/authorized_keys\"'; \
    echo -e \"${password_to_use}\" | sudo -S -u ${username} sh -c 'chown ${username}:$username \"/home/${username}/.ssh/authorized_keys\"'; \
    echo -e \"${password_to_use}\" | sudo -S -u ${username} sh -c 'chmod 600 \"/home/${username}/.ssh/authorized_keys\"'; \
    echo -e \"${password_to_use}\" | sudo -S rm /tmp/id_rsa.pub; \
    echo -e \"${password_to_use}\" | sudo -S service ssh restart; \
  "
  if [ $always_use_key -gt 0 ]; then
    write_block 2 "running first command with cert"
    ssh -i "${id_rsa_pub_location}id_rsa" -o "UserKnownHostsFile /tmp/known_hosts" "${username}"@${hostname} -p ${ssh_port} "${execString}"
    most_recent_command_value=$?
    check_for_error $most_recent_command_value "target setup" "ssh block #1"
  else
    write_block 2 "running first command with username and password"
    sshpass -p "${initial_target_password}" ssh -o "UserKnownHostsFile /tmp/known_hosts" "${initial_target_username}"@${initial_target_hostname} -p ${ssh_port} "${execString}"
    most_recent_command_value=$?
    check_for_error $most_recent_command_value "target setup" "ssh block #1"
  fi
  if [[ ! "${initial_target_hostname}" == "${hostname}" ]]; then
    {
      sshpass -p "${initial_target_password}" ssh -o "UserKnownHostsFile /tmp/known_hosts" "${initial_target_username}"@${initial_target_hostname} -p ${ssh_port} " \
        echo -e \"${password}\" | sudo -S reboot now \
      "
    } || {
      write_block 1 "rebooting target now"
    }
    wait_for_host
    ssh-keygen -f "/tmp/known_hosts" -R "$initial_target_hostname"
    ## TODO switch this back to cert management once the new and old ways are figured out
    local host_fingerprint_output=$(sshpass -p "${initial_target_password}" ssh -o "UserKnownHostsFile /tmp/known_hosts" -o "StrictHostKeyChecking=accept-new" -p ${ssh_port} "${initial_target_username}"@${hostname} "echo got fingerprint")
    most_recent_command_value=$?
    write_block 2 "$host_fingerprint_output"
    check_for_error $most_recent_command_value "target setup" "add fingerprint to known_hosts"
  fi
}

second_command_run() {
  # TODO: extra output here
  ssh ${username}@${hostname} -o "UserKnownHostsFile /tmp/known_hosts" -i "${id_rsa_pub_location}id_rsa" -p ${ssh_port} " \
    if [ ${skip_del_pi_user} -eq 0 ]; then \
      getent passwd \"${initial_target_username}\" > /dev/null 2&>1; \
      if [ \$? -eq 0 ]; then \
        echo -e \"${password}\" | sudo -S killall -u \"${initial_target_username}\"; \
        echo -e \"${password}\" | sudo -S userdel -f -r \"${initial_target_username}\"; \
      fi; \
    fi; \
    filecontent=\$(echo -e \"${password}\" | sudo -S sh -c 'cat /boot/cmdline.txt'); \
    regex=\"cgroup_enable=cpuset cgroup_memory=1 cgroup_enable=memory\"; \
    if [[ ! \" \$filecontent \" =~ \"\$regex\" ]]; then \
      echo -e \"${password}\" | sudo -S sh -c \"sed '$ s/$/ cgroup_enable=cpuset cgroup_memory=1 cgroup_enable=memory /' /boot/cmdline.txt >/boot/cmdline.txt.new && mv /boot/cmdline.txt.new /boot/cmdline.txt\"; \
    fi; \
    if [ ${skip_update} -eq 0 ]; then \
      echo -e \"${password}\" | sudo -S apt-get update; \
    fi; \
    if [ ${skip_upgrade} -eq 0 ]; then \
      echo -e \"${password}\" | sudo -S apt-get upgrade -y; \
    fi; \
    if [ ${skip_autoremove} -eq 0 ]; then \
      echo -e \"${password}\" | sudo -S apt-get autoremove -y; \
    fi; \
    filecontent=\$(echo -e \"${password}\" | sudo -S sh -c 'cat /etc/sudoers'); \
    regex=\"${username} ALL=(ALL) NOPASSWD:ALL\"; \
    if [[ ! \" \$filecontent \" =~ \"\$regex\" ]]; then \
      echo -e \"${password}\" | sudo -S cp /etc/sudoers /etc/sudoers.bak; \
      echo -e \"${password}\" | sudo -S sh -c \"echo '' >> /etc/sudoers\"; \
      echo -e \"${password}\" | sudo -S sh -c \"echo '# k3s setup no password required' >> /etc/sudoers\"; \
      echo -e \"${password}\" | sudo -S sh -c \"echo '${username} ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers\"; \
    fi;
  "
  most_recent_command_value=$?
  check_for_error $most_recent_command_value "target setup" "ssh block #2"
  if ssh ${username}@${hostname} -o "UserKnownHostsFile /tmp/known_hosts" -i "${keyname}" stat /etc/sudoers.bak \> /dev/null 2>\&1
  then
    updated_sudoers=1
  fi
}

reboot() {
  # TODO: extra output here
  {
    ssh ${username}@${hostname} -o "UserKnownHostsFile /tmp/known_hosts" -i "${keyname}" -p ${ssh_port} " \
      echo -e \"${password}\" | sudo -S reboot now \
    "
  } || {
    write_block 1 "rebooting target now"
  }
}

wait_for_host() {
  wait_for_host_ready=0
  write_block 2 "Waiting for host to be ready..."
  sleep 1
  while [ $wait_for_host_ready -eq 0 ]
  do
    write_block 2 "Waiting for host to be ready..."
    sleep .5
    if nc -zv ${hostname} ${ssh_port} 2>&1 | grep -q succeeded; then 
      wait_for_host_ready=1
    fi
  done
}

cleanup_run() {
  # this doesn't need to be done because the user needs to be able to run sudo commands for k3sup
  # if [ ${skip_update} -eq 1 ]; then
  #   write_block 2 "move the sudoers file back"
  #   ssh ${username}@${hostname} -o "UserKnownHostsFile /tmp/known_hosts" -i "${keyname}" -p ${ssh_port} " \
  #     sudo mv /etc/sudoers.bak /etc/sudoers; \
  #   "
  # fi
  write_block 2 "finished cleanup"
}

cat_remote_docs() {
  if [ $verbose -ge 2 ]; then
    if [ ! -z "$1" ]; then
      write_block 2 "$1"
    fi
    ssh ${username}@${hostname} -o "UserKnownHostsFile /tmp/known_hosts" -i "${keyname}" -p ${ssh_port} " \
      echo \"contents of /etc/sudoers\"; \
      echo \"\"; \
      echo -e \"${password}\" | sudo -S sh -c \"cat /etc/sudoers\"; \
      echo \"\"; \
      echo \"\"; \
      echo \"contents of /boot/cmdline.txt\"; \
      echo \"\"; \
      echo -e \"${password}\" | sudo -S sh -c \"cat /boot/cmdline.txt\"; \
    "
    most_recent_command_value=$?
    check_for_error $most_recent_command_value "cat remote docs" "cat remote docs"
  fi
}
