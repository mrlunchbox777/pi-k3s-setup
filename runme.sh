#!/bin/bash

$hostname="${hostname}"
$username="${username}"
$password="${password}"
$cluster_server_ip="${cluster_server_ip}"
$id_rsa_pub_location="${id_rsa_pub_location}"
$admin_username="${admin_username}"
$admin_ssh_password="${admin_ssh_password}"

delimiter="*******************************************************"

write_block() {
  echo ""
  echo "$delimiter"
  for i in "$@"
  do
    echo "* $(date) - $i"
  done
  echo "$delimiter"
  echo ""
}

write_instructions() {
  instructionArray=( "" )
  instructionArray+=( "1. Get the pi accessible" )
  instructionArray+=( "  a. Get the boot drive ready, format using the following" )
  instructionArray+=( "    i. &&& add more instruction here &&&" )
  instructionArray+=( "    ii. balenaEtcher - https://www.balena.io/etcher/" )
  instructionArray+=( "    iii. Rasbian Lite - https://www.raspberrypi.org/software/operating-systems/" )
  instructionArray+=( "  b. boot & login" )
  instructionArray+=( "    i. u: pi" )
  instructionArray+=( "    ii. p: raspberry" )
  instructionArray+=( "  c. sudo raspi-config" )
  instructionArray+=( "    i. 8 Update" )
  instructionArray+=( "    ii. 1 System Options" )
  instructionArray+=( "    iii. S4 Hostname" )
  instructionArray+=( "      1. Set to desired hostname" )
  instructionArray+=( "    iv. 3 Interface Options" )
  instructionArray+=( "    v. 2 SSH" )
  instructionArray+=( "      1. Enable SSH" )
  instructionArray+=( "    vi. 4 Performance Options" )
  instructionArray+=( "    vii. P2 GPU Memory" )
  instructionArray+=( "      1. Set to 16" )
  instructionArray+=( "  d. Reload ssh, choose one of the following" )
  instructionArray+=( "    i. sudo service ssh restart" )
  instructionArray+=( "    i. sudo reboot now" )
  instructionArray+=( "" )

  write_block "${instructionArray[@]}"
}

write_variables() {
  local masked_password=$(echo -e $password | sed "s#1/#\*/#")
  local masked_ssh_password=$(echo -e $admin_ssh_password | sed "s#1/#\*/#")

  variablesArray=( "" )
  variablesArray+=( "Using The Following Variables" )
  variablesArray+=( "" )
  variablesArray+=( "" )
  variablesArray+=( "Pi Variables" )
  variablesArray+=( "" )
  variablesArray+=( "hostname - $hostname" )
  variablesArray+=( "username - $username" )
  variablesArray+=( "password - $masked_password" )
  variablesArray+=( "*cluster_server_ip - $cluster_server_ip" )
  variablesArray+=( "" )
  variablesArray+=( "Admin Machine Variables" )
  variablesArray+=( "" )
  variablesArray+=( "*id_rsa_pub_location - $id_rsa_pub_location" )
  variablesArray+=( "admin_username - $admin_username" )
  variablesArray+=( "admin_ssh_password - $masked_ssh_password" )
  variablesArray+=( "" )

  variablesArray+=( "" )
  write_block "${variablesArray[@]}"
}
### Variables

# * hostname
#   * on the pi
# * username
#   * on the pi
# * password
#   * on the pi
# * id_rsa_pub_location
#   * on the admin machine
# * admin_username
#   * on the admin machine
# * admin_ssh_password
#   * on the admin machine
# * cluster_server_ip
#   * if set will join, if not it won't

write_block "Starting Runme"
# * &&& Write out safe variables and verify go &&&&
if [ ! -z "${id_rsa_pub_location}" ]
then
    ssh-keygen -f /home/${admin_username}/.ssh/id_rsa -N "${admin_ssh_password}"
    export id_rsa_pub_location="/home/${admin_username}/.ssh/id_rsa.pub"
fi
echo -e "${admin_ssh_password}" | ssh-add -p "${id_rsa_pub_location}"
scp ${id_rsa_pub_location}/id_rsa.pub ${admin_username}@${hostname}:/home/${username}/.ssh/authorized_keys

ssh pi@{hostname} -praspberry
echo -e raspberry | sudo -S useradd -m -G sudo ${username}
echo -e ${password} | passwd ${username}
echo -e raspberry | sudo -S sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
exit

ssh ${username}@${hostname} -i "${id_rsa_pub_location}"
echo -e ${password} | sudo -S userdel -r pi
echo -n " cgroup_enable=cpuset cgroup_memory=1 cgroup_enable=memory " >> /boot/cmdline.txt
echo -e ${password} | sudo -S apt-get update
echo -e ${password} | sudo -S apt-get upgrade -y
echo -e ${password} | sudo -S apt-get autoremove -y
sudo reboot now

write_block "Waiting 5 seconds for reboot..."
sleep 5
if [ -z /usr/local/bin/k3sup ]
then
    write_block "Installing k3s"
    curl -sLS https://get.k3sup.dev | sh
    sudo install k3sup /usr/local/bin/
fi
k3sup install --host ${hostname} --user ${username} --ssh-key ${id_rsa_pub_location} --cluster
if [ ! -z "${cluster_server_ip}" ]
then
    k3sup join --host ${hostname} --user ${username} --server-host ${hostname} --server-user ${username} --ssh-key ${id_rsa_pub_location} --server
fi

### After

# * &&& mention basically done &&&&
# * &&& update sshd_config to not allow passwords &&&
# * 
# * &&& Write out safe variables and notify successful end &&&&
# * &&& Suggest that the security conscious change their secrets (password, sshkey, find others) &&&
