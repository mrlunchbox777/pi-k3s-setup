#!/bin/bash

$hostname="${hostname}"
$username="${username}"
$password="${password}"
$cluster_server_ip="${cluster_server_ip}"
$id_rsa_pub_location="${id_rsa_pub_location}"
$admin_username="${admin_username}"
$admin_ssh_password="${admin_ssh_password}"
$run_type="${run_type:-help}"

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
  instructionArray+=( "    ii. sudo reboot now" )
  instructionArray+=( "2. Set variables" )
  instructionArray+=( "  a. Run this utility (see 3) with the run_type variable set to run to check variable values," )
  instructionArray+=( "    and then answer no on the prompt proceed" )
  instructionArray+=( "  b. Some values have good defaults which will be shown at the verification string" )
  instructionArray+=( "  c. Every value must be set unless it's stated otherwise" )
  instructionArray+=( "  d. Every value can be set in the following ways" )
  instructionArray+=( "    i. Set the environment variable with the same name as the variable" )
  instructionArray+=( "    ii. (Docker only) Set the environment variable in the .env file" )
  instructionArray+=( "      with the same name as the variable" )
  instructionArray+=( "    iii. (Host only) Set the parameter with the same name as the variable" )
  instructionArray+=( "3. Run Utility" )
  instructionArray+=( "  a. The utility can be run several different ways" )
  instructionArray+=( "    i. Docker" )
  instructionArray+=( "      1. Navigate to the root of the repo" )
  instructionArray+=( "      2. cp template.env .env" )
  instructionArray+=( "      3. Modify .env as desired (see 2)" )
  instructionArray+=( "      4. docker-compose up" )
  instructionArray+=( "    ii. Host" )
  instructionArray+=( "      1. Set the variables (see 2)" )
  instructionArray+=( "      2. Run the script" )
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
  variablesArray+=( "cluster_server_ip - $cluster_server_ip" )
  variablesArray+=( "  note: cluster_server_ip can be left empty and it won't join a cluster" )
  variablesArray+=( "" )
  variablesArray+=( "Admin Machine Variables" )
  variablesArray+=( "" )
  variablesArray+=( "id_rsa_pub_location - $id_rsa_pub_location" )
  variablesArray+=( "admin_username - $admin_username" )
  variablesArray+=( "admin_ssh_password - $masked_ssh_password" )
  variablesArray+=( "" )
  variablesArray+=( "Utility Variables" )
  variablesArray+=( "" )
  variablesArray+=( "run_type - $run_type" )
  variablesArray+=( "" )

  variablesArray+=( "" )
  write_block "${variablesArray[@]}"
}

write_block "Starting Runme"
$cluster_server_ip="${cluster_server_ip}"
$id_rsa_pub_location="${id_rsa_pub_location}"
$admin_username="${admin_username}"
$admin_ssh_password="${admin_ssh_password}"
$run_type="${run_type:-help}"
while getopts "hostname:username:password:" opts; do
   case ${opts} in
      hostname) hostname=${OPTARG} ;;
      username) username=${OPTARG} ;;
      password) password=${OPTARG} ;;
      [?]) write_block "argument $opts unknown" ;;
   esac
done
while :; do
  case $1 in
    -h|-\?|--help)
      show_help    # Display a usage synopsis.
      exit
      ;;
   -f|--file)       # Takes an option argument; ensure it has been specified.
      if [ "$2" ]; then
        file=$2
        shift
      else
        die 'ERROR: "--file" requires a non-empty option argument.'
      fi
      ;;
    --file=?*)
      file=${1#*=} # Delete everything up to "=" and assign the remainder.
      ;;
    --file=)         # Handle the case of an empty --file=
      die 'ERROR: "--file" requires a non-empty option argument.'
      ;;
    -v|--verbose)
      verbose=$((verbose + 1))  # Each -v adds 1 to verbosity.
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
