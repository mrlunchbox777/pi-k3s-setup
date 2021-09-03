#!/bin/bash

hostname="${HOSTNAME}"
username="${USERNAME}"
password="${PASSWORD}"
cluster_server_name="${CLUSTER_SERVER_NAME}"
id_rsa_pub_location="${ID_RSA_PUB_LOCATION}"
admin_username="${ADMIN_USERNAME}"
admin_ssh_password="${ADMIN_SSH_PASSWORD}"
run_type="${RUN_TYPE:-help}"
verbose="${VERBOSE:-0}"
interactive="${INTERACTIVE:-1}"
skip_update="${SKIP_UPDATE:-0}"
skip_upgrade="${SKIP_UPGRADE:-0}"
skip_autoremove="${SKIP_AUTOREMOVE:-0}"
myserver_country="${MYSERVER_COUNTRY:-"US"}"
myserver_state="${MYSERVER_STATE:-"UT"}"
myserver_location="${MYSERVER_LOCATION:-"SLC"}"
myserver_organizational_unit="${MYSERVER_ORGANIZATIONAL_UNIT:-"IT"}"
myserver_fully_qualified_domain_name="${MYSERVER_FULLY_QUALIFIED_DOMAIN_NAME:-"k3s.local"}"
myserver_organization_name="${MYSERVER_ORGANIZATION_NAME:-"k3s"}"
skip_del_pi_user="${SKIP_DEL_PI_USER:-0}"
skip_deny_ssh_passwords="${SKIP_DENY_SSH_PASSWORDS:-0}"
context_name="${CONTEXT_NAME:-"default"}"
ssh_port="${SSH_PORT:-22}"
cluster_ssh_port="${CLUSTER_SSH_PORT:-22}"
initial_target_username="${INITIAL_TARGET_USERNAME:-"pi"}"
initial_target_password="${INITIAL_TARGET_PASSWORD:-"raspberry"}"
cluster_username="${CLUSTER_USERNAME:-"${USERNAME}"}"
always_use_key="${ALWAYS_USE_KEY:-0}"
install_as_cluster="${INSTALL_AS_CLUSTER:-1}"
join_as_server="${JOIN_AS_SERVER:-1}"
final_reboot="${FINAL_REBOOT:-0}"
wait_for_final_reboot="${WAIT_FOR_FINAL_REBOOT:-0}"
delimiter="*******************************************************"
force_help=0
updated_sudoers=0
displayname="${hostname}"
mypassword="${admin_ssh_password}"
keyname="${id_rsa_pub_location}id_rsa"
pubkeyname="${id_rsa_pub_location}id_rsa.pub"
requestname="${id_rsa_pub_location}request.csr"
publiccertname="${id_rsa_pub_location}cert.crt"
pfxname="${id_rsa_pub_location}pkcs.pfx"

pi_k3s_base_dir="${BASH_SOURCE[0]}"
for pi_k3s_setup_lib_f in $(ls -p "$pi_k3s_base_dir/sh/" | grep -v /); do
  source "$pi_k3s_base_dir/sh/$pi_k3s_setup_lib_f";
done

# Still requires variables
confirm_run() {
  if [ $interactive -gt 0 ]; then
    read -r -p "Are you sure? [y/N] " response
    case "$response" in
      [yY][eE][sS]|[yY]) 
        write_block 2 "Confirmation accepted, continuing..."
        ;;
      *)
        die "Run cancelled, exiting..."
        ;;
    esac
  else
    write_block 2 "Non-interactive skipping confirmation..."
  fi
}

# Run commands
update_known_hosts() {
  if [ -f "/tmp/known_hosts" ]; then
    rm /tmp/known_hosts
  fi

  write_block 2 "add fingerprint to known_hosts"
  # TODO: extra output here
  if [ $always_use_key -gt 0 ]; then
    local host_fingerprint_output=$(ssh -i "${id_rsa_pub_location}id_rsa" -o "UserKnownHostsFile /tmp/known_hosts" -o "StrictHostKeyChecking=accept-new" -p ${ssh_port} "${username}"@${hostname} "echo got fingerprint")
    most_recent_command_value=$?
    write_block 2 "$host_fingerprint_output"
    check_for_error $most_recent_command_value "target setup" "add fingerprint to known_hosts"
  else
    local host_fingerprint_output=$(sshpass -p "${initial_target_password}" ssh -o "UserKnownHostsFile /tmp/known_hosts" -o "StrictHostKeyChecking=accept-new" -p ${ssh_port} "${initial_target_username}"@${hostname} "echo got fingerprint")
    most_recent_command_value=$?
    write_block 2 "$host_fingerprint_output"
    check_for_error $most_recent_command_value "target setup" "add fingerprint to known_hosts"
  fi
}

create_myserver_cnf() {
  write_block 2 "creating the openssl configuration"
  echo "# OpenSSL configuration file for creating a CSR for a server certificate" >> myserver.cnf
  echo "# Adapt at least the FQDN and ORGNAME lines, and then run" >> myserver.cnf 
  echo "# openssl req -new -config myserver.cnf -keyout myserver.key -out myserver.csr" >> myserver.cnf
  echo "# on the command line." >> myserver.cnf
  echo "" >> myserver.cnf

  echo "# the fully qualified server (or service) name" >> myserver.cnf
  echo "FQDN = $myserver_fully_qualified_domain_name" >> myserver.cnf
  echo "" >> myserver.cnf

  echo "# the name of your organization" >> myserver.cnf
  echo "# (see also https://www.switch.ch/pki/participants/)" >> myserver.cnf
  echo "ORGNAME = $myserver_organization_name" >> myserver.cnf
  echo "" >> myserver.cnf
  
  echo "# subjectAltName entries: to add DNS aliases to the CSR, delete" >> myserver.cnf
  echo "# the '#' character in the ALTNAMES line, and change the subsequent" >> myserver.cnf
  echo "# 'DNS:' entries accordingly. Please note: all DNS names must" >> myserver.cnf
  echo "# resolve to the same IP address as the FQDN." >> myserver.cnf
  echo "ALTNAMES = DNS:\$FQDN   # , DNS:bar.example.org , DNS:www.foo.example.org" >> myserver.cnf
  echo "" >> myserver.cnf

  echo "[ req ]" >> myserver.cnf
  echo "default_bits = 2048" >> myserver.cnf
  echo "default_md = sha256" >> myserver.cnf
  echo "prompt = no" >> myserver.cnf
  echo "encrypt_key = yes" >> myserver.cnf
  echo "distinguished_name = dn" >> myserver.cnf
  echo "req_extensions = req_ext" >> myserver.cnf
  echo "" >> myserver.cnf

  echo "[ dn ]" >> myserver.cnf
  echo "C = $myserver_country" >> myserver.cnf
  echo "ST = $myserver_state" >> myserver.cnf
  echo "L = $myserver_location" >> myserver.cnf
  echo "O = \$ORGNAME" >> myserver.cnf
  echo "CN = \$FQDN" >> myserver.cnf
  echo "OU = $myserver_organizational_unit" >> myserver.cnf
  echo "" >> myserver.cnf

  echo "[ req_ext ]" >> myserver.cnf
  echo "subjectAltName = \$ALTNAMES" >> myserver.cnf
  echo "" >> myserver.cnf
}

create_and_send_the_cert() {
  write_block 2 "prep the cert"
  if [ -z "${id_rsa_pub_location}" ]; then
    id_rsa_pub_location="/home/${admin_username}/.ssh/"
  fi
  if [ ! -f "${id_rsa_pub_location}" ]; then
    mkdir -p "${id_rsa_pub_location}"
  fi
  displayname="${hostname}"
  mypassword="${admin_ssh_password}"
  keyname="${id_rsa_pub_location}id_rsa"
  pubkeyname="${id_rsa_pub_location}id_rsa.pub"
  requestname="${id_rsa_pub_location}request.csr"
  publiccertname="${id_rsa_pub_location}cert.crt"
  pfxname="${id_rsa_pub_location}pkcs.pfx"
  if [ ! -f "${keyname}" ]; then
    create_myserver_cnf
    write_block 2 "creating self-signed cert files"
    local keygen_output=$(openssl genrsa -out "$keyname" 2048)
    most_recent_command_value=$?
    write_block 2 "$keygen_output"
    check_for_error $most_recent_command_value "prep the cert" "keygen - rsa"
    local keygen_output=$(openssl req -new -key "$keyname" -out "$requestname" -config myserver.cnf -passout pass:"$mypassword")
    most_recent_command_value=$?
    write_block 2 "$keygen_output"
    check_for_error $most_recent_command_value "prep the cert" "keygen - csr"
    local keygen_output=$(openssl x509 -req -days 365 -in "$requestname" -signkey "$keyname" -out "$publiccertname")
    most_recent_command_value=$?
    write_block 2 "$keygen_output"
    check_for_error $most_recent_command_value "prep the cert" "keygen - crt"
    local keygen_output=$(openssl pkcs12 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -export -in "$publiccertname" -inkey "$keyname" -out "$pfxname" -name "$displayname" -passin pass:"$mypassword" -passout pass:"$mypassword")
    most_recent_command_value=$?
    write_block 2 "$keygen_output"
    check_for_error $most_recent_command_value "prep the cert" "keygen - pfx"
    local keygen_output=$(ssh-keygen -y -f "$keyname" > "$pubkeyname")
    most_recent_command_value=$?
    write_block 2 "$keygen_output"
    check_for_error $most_recent_command_value "prep the cert" "keygen - pub"
  fi

  write_block 2 "copy the public key to the target"
  # TODO: extra output here
  if [ $always_use_key -gt 0 ]; then
    write_block 2 "sending the cert with cert"
    local scp_output=$(scp -i "${id_rsa_pub_location}id_rsa" -o "UserKnownHostsFile /tmp/known_hosts" -P ${ssh_port} "${pubkeyname}" "${username}"@${hostname}:/tmp/id_rsa.pub)
    most_recent_command_value=$?
    write_block 2 "scp_output - $scp_output"
    check_for_error $most_recent_command_value "target setup" "scp"
  else
    write_block 2 "moving the keys out for password auth"
    mkdir -p "/tmp${id_rsa_pub_location}"
    mv "${pubkeyname}" "/tmp${pubkeyname}"
    mv "${keyname}" "/tmp${keyname}"
    mv "${requestname}" "/tmp${requestname}"
    mv "${publiccertname}" "/tmp${publiccertname}"
    mv "${pfxname}" "/tmp${pfxname}"

    write_block 2 "sending the cert with username and password"
    local scp_output=$(sshpass -p "${initial_target_password}" scp -o "UserKnownHostsFile /tmp/known_hosts" -P ${ssh_port} "/tmp${pubkeyname}" "${initial_target_username}"@${hostname}:/tmp/id_rsa.pub)
    most_recent_command_value=$?
    write_block 2 "scp_output - $scp_output"
    check_for_error $most_recent_command_value "target setup" "scp"
  fi
}

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
    sshpass -p "${initial_target_password}" ssh -o "UserKnownHostsFile /tmp/known_hosts" "${initial_target_username}"@${hostname} -p ${ssh_port} "${execString}"
    most_recent_command_value=$?
    check_for_error $most_recent_command_value "target setup" "ssh block #1"
  fi
}

setup_cert_for_use() {
  if [ $always_use_key -lt 1 ]; then
    write_block 2 "moving the keys back cert auth"
    mv "/tmp${pubkeyname}" "${pubkeyname}"
    mv "/tmp${keyname}" "${keyname}"
    mv "/tmp${requestname}" "${requestname}"
    mv "/tmp${publiccertname}" "${publiccertname}"
    mv "/tmp${pfxname}" "${pfxname}"
  fi

  write_block 2 "set up use of the cert"
  # TODO: extra output here
  eval `ssh-agent -s` >> /dev/null
  write_block 2 "ssh-agent output - $ssh_output"
  if [ -z "${admin_ssh_password}" ]; then
    write_block 2 "Using id_rsa without password..."
    local sshadd_output=$(ssh-add "${id_rsa_pub_location}id_rsa")
    most_recent_command_value=$?
    write_block 2 "ssh-add output - $sshadd_output"
    check_for_error $most_recent_command_value "target setup" "ssh-add without password"
  else
    local sshadd_output=$(ssh_add_pass "${id_rsa_pub_location}id_rsa" "${admin_ssh_password}")
    most_recent_command_value=$?
    write_block 2 "ssh-add output - $sshadd_output"
    check_for_error $most_recent_command_value "target setup" "ssh-add with password"
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

setup_target() {
  wait_for_host
  update_known_hosts
  create_and_send_the_cert
  first_command_run
  setup_cert_for_use
  cat_remote_docs "before second command"
  second_command_run
  cat_remote_docs "after second command"
  reboot
  install_k3sup_host
  wait_for_host
  {
    run_k3sup 0
  } || {
    write_block 0 "k3sup failed on first run. This happens sometimes because of timeouts, boot time, cgroups, etc. Sleeping and trying again"
    sleep 30
    run_k3sup 1
  }
  cat_remote_docs "after k3sup"
  cleanup_run
  cat_remote_docs "after cleanup"
  if [ $final_reboot -gt 0 ]; then
    reboot
  fi
  if [ $wait_for_final_reboot -gt 0 ]; then
    wait_for_host
  fi
}

post_run() {
  write_block 1 "Successful Run"
  show_variables
  postRunArray=( "" )
  postRunArray+=( "Successful Run" )
  postRunArray+=( "For the security conscious consider changing the following:" )
  postRunArray+=( "  - password on the target" )
  postRunArray+=( "  - the password for the sshkey" )
  postRunArray+=( "If running from docker you will find your ssh keys and kubeconfig in the .docker-data folder" )

  postRunArray+=( "" )
  write_block 1 "${postRunArray[@]}"
}

write_block 2 "parse parameters"
while :; do
  case $1 in
    -h|-\?|--help)
      force_help=1
      ;;
    -hn|--hostname)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        hostname=$2
        shift
      else
        die 'ERROR: "--hostname" requires a non-empty option argument.'
      fi
      ;;
    --hostname=?*)
      hostname=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --hostname=)         # Handle the case of an empty --file=
      die 'ERROR: "--hostname" requires a non-empty option argument.'
      ;;
    -u|--username)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        username=$2
        shift
      else
        die 'ERROR: "--username" requires a non-empty option argument.'
      fi
      ;;
    --username=?*)
      username=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --username=)         # Handle the case of an empty --file=
      die 'ERROR: "--username" requires a non-empty option argument.'
      ;;
    -p|--password)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        password=$2
        shift
      else
        die 'ERROR: "--password" requires a non-empty option argument.'
      fi
      ;;
    --password=?*)
      password=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --password=)         # Handle the case of an empty --file=
      die 'ERROR: "--password" requires a non-empty option argument.'
      ;;
    -c|--cluster_server_name)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        cluster_server_name=$2
        shift
      else
        die 'ERROR: "--cluster_server_name" requires a non-empty option argument.'
      fi
      ;;
    --cluster_server_name=?*)
      cluster_server_name=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --cluster_server_name=)         # Handle the case of an empty --file=
      die 'ERROR: "--cluster_server_name" requires a non-empty option argument.'
      ;;
    -i|--id_rsa_pub_location)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        id_rsa_pub_location=$2
        shift
      else
        die 'ERROR: "--id_rsa_pub_location" requires a non-empty option argument.'
      fi
      ;;
    --id_rsa_pub_location=?*)
      id_rsa_pub_location=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --id_rsa_pub_location=)         # Handle the case of an empty --file=
      die 'ERROR: "--id_rsa_pub_location" requires a non-empty option argument.'
      ;;
    -a|--admin_username)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        admin_username=$2
        shift
      else
        die 'ERROR: "--admin_username" requires a non-empty option argument.'
      fi
      ;;
    --admin_username=?*)
      admin_username=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --admin_username=)         # Handle the case of an empty --file=
      die 'ERROR: "--admin_username" requires a non-empty option argument.'
      ;;
    -s|--admin_ssh_password)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        admin_ssh_password=$2
        shift
      else
        die 'ERROR: "--admin_ssh_password" requires a non-empty option argument.'
      fi
      ;;
    --admin_ssh_password=?*)
      admin_ssh_password=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --admin_ssh_password=)         # Handle the case of an empty --file=
      die 'ERROR: "--admin_ssh_password" requires a non-empty option argument.'
      ;;
    -r|--run_type)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        run_type=$2
        shift
      else
        die 'ERROR: "--run_type" requires a non-empty option argument.'
      fi
      ;;
    --run_type=?*)
      run_type=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --run_type=)         # Handle the case of an empty --file=
      die 'ERROR: "--run_type" requires a non-empty option argument.'
      ;;
    -y|--interactive)       # Takes an option argument; ensure it has been specified.
        interactive=1
      ;;
    -v|--verbose)
      verbose=$((verbose + 1))  # Each -v adds 1 to verbosity.
      ;;
    -ud|--skip_update)       # Takes an option argument; ensure it has been specified.
        skip_update=1
      ;;
    -ug|--skip_upgrade)       # Takes an option argument; ensure it has been specified.
        skip_upgrade=1
      ;;
    -ar|--skip_autoremove)       # Takes an option argument; ensure it has been specified.
        skip_autoremove=1
      ;;
    -msc|--myserver_country)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        myserver_country=$2
        shift
      else
        die 'ERROR: "--myserver_country" requires a non-empty option argument.'
      fi
      ;;
    --myserver_country=?*)
      myserver_country=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --myserver_country=)         # Handle the case of an empty --file=
      die 'ERROR: "--myserver_country" requires a non-empty option argument.'
      ;;
    -mss|--myserver_state)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        myserver_state=$2
        shift
      else
        die 'ERROR: "--myserver_state" requires a non-empty option argument.'
      fi
      ;;
    --myserver_state=?*)
      myserver_state=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --myserver_state=)         # Handle the case of an empty --file=
      die 'ERROR: "--myserver_state" requires a non-empty option argument.'
      ;;
    -msl|--myserver_location)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        myserver_location=$2
        shift
      else
        die 'ERROR: "--myserver_location" requires a non-empty option argument.'
      fi
      ;;
    --myserver_location=?*)
      myserver_location=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --myserver_location=)         # Handle the case of an empty --file=
      die 'ERROR: "--myserver_location" requires a non-empty option argument.'
      ;;
    -msou|--myserver_organizational_unit)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        myserver_organizational_unit=$2
        shift
      else
        die 'ERROR: "--myserver_organizational_unit" requires a non-empty option argument.'
      fi
      ;;
    --myserver_organizational_unit=?*)
      myserver_organizational_unit=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --myserver_organizational_unit=)         # Handle the case of an empty --file=
      die 'ERROR: "--myserver_organizational_unit" requires a non-empty option argument.'
      ;;
    -msfqdn|--myserver_fully_qualified_domain_name)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        myserver_fully_qualified_domain_name=$2
        shift
      else
        die 'ERROR: "--myserver_fully_qualified_domain_name" requires a non-empty option argument.'
      fi
      ;;
    --myserver_fully_qualified_domain_name=?*)
      myserver_fully_qualified_domain_name=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --myserver_fully_qualified_domain_name=)         # Handle the case of an empty --file=
      die 'ERROR: "--myserver_fully_qualified_domain_name" requires a non-empty option argument.'
      ;;
    -mson|--myserver_organization_name)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        myserver_organization_name=$2
        shift
      else
        die 'ERROR: "--myserver_organization_name" requires a non-empty option argument.'
      fi
      ;;
    --myserver_organization_name=?*)
      myserver_organization_name=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --myserver_organization_name=)         # Handle the case of an empty --file=
      die 'ERROR: "--myserver_organization_name" requires a non-empty option argument.'
      ;;
    -sdpu|--skip_del_pi_user)       # Takes an option argument; ensure it has been specified.
        skip_del_pi_user=1
      ;;
    -sdsp|--skip_deny_ssh_passwords)       # Takes an option argument; ensure it has been specified.
        skip_deny_ssh_passwords=1
      ;;
    -cn|--context_name)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        context_name=$2
        shift
      else
        die 'ERROR: "--context_name" requires a non-empty option argument.'
      fi
      ;;
    --context_name=?*)
      context_name=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --context_name=)         # Handle the case of an empty --file=
      die 'ERROR: "--context_name" requires a non-empty option argument.'
      ;;
    -sp|--ssh_port)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        ssh_port=$2
        shift
      else
        die 'ERROR: "--ssh_port" requires a non-empty option argument.'
      fi
      ;;
    --ssh_port=?*)
      ssh_port=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --ssh_port=)         # Handle the case of an empty --file=
      die 'ERROR: "--ssh_port" requires a non-empty option argument.'
      ;;
    -csp|--cluster_ssh_port)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        cluster_ssh_port=$2
        shift
      else
        die 'ERROR: "--cluster_ssh_port" requires a non-empty option argument.'
      fi
      ;;
    --cluster_ssh_port=?*)
      cluster_ssh_port=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --cluster_ssh_port=)         # Handle the case of an empty --file=
      die 'ERROR: "--cluster_ssh_port" requires a non-empty option argument.'
      ;;
    -itu|--initial_target_username)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        initial_target_username=$2
        shift
      else
        die 'ERROR: "--initial_target_username" requires a non-empty option argument.'
      fi
      ;;
    --initial_target_username=?*)
      initial_target_username=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --initial_target_username=)         # Handle the case of an empty --file=
      die 'ERROR: "--initial_target_username" requires a non-empty option argument.'
      ;;
    -itp|--initial_target_password)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        initial_target_password=$2
        shift
      else
        die 'ERROR: "--initial_target_password" requires a non-empty option argument.'
      fi
      ;;
    --initial_target_password=?*)
      initial_target_password=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --initial_target_password=)         # Handle the case of an empty --file=
      die 'ERROR: "--initial_target_password" requires a non-empty option argument.'
      ;;
    -cu|--cluster_username)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        cluster_username=$2
        shift
      else
        die 'ERROR: "--cluster_username" requires a non-empty option argument.'
      fi
      ;;
    --cluster_username=?*)
      cluster_username=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --cluster_username=)         # Handle the case of an empty --file=
      die 'ERROR: "--cluster_username" requires a non-empty option argument.'
      ;;
    -sdsp|--always_use_key)       # Takes an option argument; ensure it has been specified.
        always_use_key=1
      ;;
    -iac|--install_as_cluster)       # Takes an option argument; ensure it has been specified.
        install_as_cluster=1
      ;;
    -jas|--join_as_server)       # Takes an option argument; ensure it has been specified.
        join_as_server=1
      ;;
    -fr|--final_reboot)       # Takes an option argument; ensure it has been specified.
        final_reboot=1
      ;;
    -wfr|--wait_for_final_reboot)       # Takes an option argument; ensure it has been specified.
        wait_for_final_reboot=1
      ;;
    --)              # End of all options.
      shift
      break
      ;;
    -?*)
      printf 'WARN: Unknown option (ignored): %s\n' "$1" >&2
      ;;
    *)               # Default case: No more options, so break out of the loop.
      break
  esac
  shift
done

write_block 1 "Starting Up"

if [ $force_help -eq 1 ]; then
  run_type="help"
fi

if [ $run_type = "run" ]; then
  show_variables
  validate_variables
  confirm_run
  setup_target
  post_run
else
  if [ $verbose -lt 1 ]; then
    verbose=$((verbose + 1))
  fi
  show_variables
  show_help
fi
