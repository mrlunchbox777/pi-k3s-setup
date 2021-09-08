update_known_hosts() {
  if [ -f "/tmp/known_hosts" ]; then
    rm /tmp/known_hosts
  fi

  write_block 2 "add fingerprint to known_hosts"
  # TODO: extra output here
  if [ $always_use_key -gt 0 ]; then
    local host_fingerprint_output=$(ssh -i "${id_rsa_pub_location}id_rsa" -o "UserKnownHostsFile /tmp/known_hosts" -o "StrictHostKeyChecking=accept-new" -p ${ssh_port} "${username}"@${initial_target_hostname} "echo got fingerprint")
    most_recent_command_value=$?
    write_block 2 "$host_fingerprint_output"
    check_for_error $most_recent_command_value "target setup" "add fingerprint to known_hosts"
  else
    local host_fingerprint_output=$(sshpass -p "${initial_target_password}" ssh -o "UserKnownHostsFile /tmp/known_hosts" -o "StrictHostKeyChecking=accept-new" -p ${ssh_port} "${initial_target_username}"@${initial_target_hostname} "echo got fingerprint")
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
    local scp_output=$(sshpass -p "${initial_target_password}" scp -o "UserKnownHostsFile /tmp/known_hosts" -P ${ssh_port} "/tmp${pubkeyname}" "${initial_target_username}"@${initial_target_hostname}:/tmp/id_rsa.pub)
    most_recent_command_value=$?
    write_block 2 "scp_output - $scp_output"
    check_for_error $most_recent_command_value "target setup" "scp"
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
