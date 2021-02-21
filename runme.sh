#!/bin/bash

hostname="${hostname}"
username="${username}"
password="${password}"
cluster_server_name="${cluster_server_name}"
id_rsa_pub_location="${id_rsa_pub_location}"
admin_username="${admin_username}"
admin_ssh_password="${admin_ssh_password}"
run_type="${run_type:-help}"
verbose="${verbose:-0}"
interactive="${interactive:-1}"
skip_update="${skip_update:-0}"
skip_upgrade="${skip_upgrade:-0}"
skip_autoremove="${skip_autoremove:-0}"
myserver_country="${myserver_country:-"US"}"
myserver_state="${myserver_state:-"UT"}"
myserver_location="${myserver_location:-"SLC"}"
myserver_organizational_unit="${myserver_organizational_unit:-"IT"}"
myserver_fully_qualified_domain_name="${myserver_fully_qualified_domain_name:-"k3s.local"}"
myserver_organization_name="${myserver_organization_name:-"k3s"}"
skip_del_pi_user="${skip_del_pi_user:-0}"
skip_deny_ssh_passwords="${skip_deny_ssh_passwords:-0}"
context_name="${context_name:-"default"}"
ssh_port="${ssh_port:-22}"
cluster_ssh_port="${cluster_ssh_port:-22}"
initial_target_username="${initial_target_username:-"pi"}"
initial_target_password="${initial_target_password:-"raspberry"}"
cluster_username="${cluster_username:-"${username}"}"
always_use_key="${always_use_key:-0}"
install_as_cluster="${install_as_cluster:-1}"
join_as_server="${join_as_server:-1}"
final_reboot="${final_reboot:-0}"
wait_for_final_reboot="${wait_for_final_reboot:-0}"
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

write_block() {
  if [ $1 -le $verbose ]; then
    set -- "${@:2}"
    prefix=""
    if [ $verbose -ge 2 ]; then
      prefix="* $(date) - "
      echo ""
      echo "$delimiter"
    fi

    for i in "$@"
    do
      echo "${prefix}${i}"
    done

    if [ $verbose -ge 2 ]; then
      echo "$delimiter"
    fi
    echo ""
  fi
}

die() {
  write_block 0 "$1"
  printf '%s\n' "$1" >&2
  exit 1
}

check_for_error() {
  write_block 2 "Just ran $3"
  if [ $1 -gt 0 ]; then
    die "An error occurred during $2. Check logs for more detail. It is unknown what state the target or host is in, and will require manual validation."
  fi
}

is_valid_username() {
  local re='^[[:lower:]_][[:lower:][:digit:]_-]{1,15}$'
  (( ${#1} > 16 )) && return 1
  [[ $1 =~ $re ]] # return value of this comparison is used for the function
}

ssh_add_pass() {
  local ssh_file="$1"
  local ssh_password="$2"
  SSH_ASKPASS=./ssh_give_pass.sh ssh-add "$ssh_file" <<< "$ssh_password"
}

show_help() {
  instructionArray=( "" )
  instructionArray+=( "1. Get the target accessible" )
  instructionArray+=( "  a. Get the boot drive ready, format the drive using the following" )
  instructionArray+=( "    i. balenaEtcher - https://www.balena.io/etcher/" )
  instructionArray+=( "    ii. Rasbian Lite - https://www.raspberrypi.org/software/operating-systems/" )
  instructionArray+=( "  b. boot & login" )
  instructionArray+=( "    i. u: pi" )
  instructionArray+=( "    ii. p: raspberry" )
  instructionArray+=( "  c. sudo raspi-config" )
  instructionArray+=( "    i. 8 Update" )
  instructionArray+=( "    ii. 1 System Options" )
  instructionArray+=( "      1. S4 Hostname" )
  instructionArray+=( "        a. Set to desired hostname" )
  instructionArray+=( "    iii. 3 Interface Options" )
  instructionArray+=( "      1. 2 SSH" )
  instructionArray+=( "        a. Enable SSH" )
  instructionArray+=( "    iv. 4 Performance Options" )
  instructionArray+=( "      1. P2 GPU Memory" )
  instructionArray+=( "        a. Set to 16" )
  instructionArray+=( "  d. Reload ssh, choose one of the following" )
  instructionArray+=( "    i. sudo service ssh restart" )
  instructionArray+=( "    ii. sudo reboot now" )
  instructionArray+=( "2. Set variables" )
  instructionArray+=( "  a. Validate that all of your variables have the correct value (run with -h)" )
  instructionArray+=( "  b. Some values have good defaults which will be shown at the verification string" )
  instructionArray+=( "  c. Every value must be set unless it's stated otherwise" )
  instructionArray+=( "  d. Every value can be set, unless it's stated otherwise, in the following ways" )
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
  instructionArray+=( "4. Get Data" )
  instructionArray+=( "  a. Docker" )
  instructionArray+=( "    i. You will have to run get_docker_data.sh after running the docker-compose" )
  instructionArray+=( "    ii. You will find all data in the .docker-data folder after running" )
  instructionArray+=( "      1. The subfolder .ssh in .docker-data will have all of the ssh data" )
  instructionArray+=( "      2. The subfolder kubeconfig in .docker-data will have kubeconfig data" )
  instructionArray+=( "  b. Host" )
  instructionArray+=( "    i. You will find all data in the following folders after running" )
  instructionArray+=( "      1. The folder at \$id_rsa_pub_location (${id_rsa_pub_location}) will have all of the ssh data" )
  instructionArray+=( "      2. The folder /kubeconfig will have kubeconfig data" )
  instructionArray+=( "" )

  write_block 1 "${instructionArray[@]}"
}

# Still requires variables
show_variables() {
  local masked_password=$(echo -e $password | sed "s/^.*/\***/#")
  local masked_ssh_password=$(echo -e $admin_ssh_password | sed "s/^.*/\***/#")

  variablesArray=( "" )
  variablesArray+=( "----- Using The Following Variables -----" )
  variablesArray+=( "" )
  variablesArray+=( "Any of these parameters can be provided by environment variables." )
  variablesArray+=( "The environment variable name is the same as the long name, e.g. hostname." )
  variablesArray+=( "" )
  variablesArray+=( "HELP -h/-?/-help" )
  variablesArray+=( "" )
  variablesArray+=( "" )
  variablesArray+=( "" )
  variablesArray+=( "--- Target Variables ---" )
  variablesArray+=( "" )
  variablesArray+=( "" )
  variablesArray+=( "hostname=$hostname" )
  variablesArray+=( "  required" )
  variablesArray+=( "  -hn/--hostname" )
  variablesArray+=( "  desc: the DNS addressable name of the target" )
  variablesArray+=( "" )
  variablesArray+=( "username=$username" )
  variablesArray+=( "  required" )
  variablesArray+=( "  -u/--username" )
  variablesArray+=( "  desc: the username for the new account on the target" )
  variablesArray+=( "" )
  variablesArray+=( "password=$masked_password" )
  variablesArray+=( "  required" )
  variablesArray+=( "  -p/--password" )
  variablesArray+=( "  desc: the password for the new account on the target" )
  variablesArray+=( "" )
  variablesArray+=( "cluster_server_name=$cluster_server_name" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -c/--cluster_server_name" )
  variablesArray+=( "  desc: the DNS addressable name of the cluster" )
  variablesArray+=( "  note: cluster_server_name can be left empty and the target won't join a cluster" )
  variablesArray+=( "" )
  variablesArray+=( "" )
  variablesArray+=( "--- Admin Machine Variables ---" )
  variablesArray+=( "" )
  variablesArray+=( "" )
  variablesArray+=( "id_rsa_pub_location=$id_rsa_pub_location" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -i/--id_rsa_pub_location" )
  variablesArray+=( "  desc: the directory of the id_rsa to use" )
  variablesArray+=( "  note: if left empty it will create an id_rsa at /home/\${admin_username}/.ssh/" )
  variablesArray+=( "" )
  variablesArray+=( "admin_username=$admin_username" )
  variablesArray+=( "  required" )
  variablesArray+=( "  -a/--admin_username" )
  variablesArray+=( "  desc: the username to use on the Admin Machine" )
  variablesArray+=( "" )
  variablesArray+=( "admin_ssh_password=$masked_ssh_password" )
  variablesArray+=( "  required" )
  variablesArray+=( "  -s/--admin_ssh_password" )
  variablesArray+=( "  desc: the password to use for the id_rsa in \${id_rsa_pub_location}" )
  variablesArray+=( "" )
  variablesArray+=( "" )
  variablesArray+=( "--- Utility Variables ---" )
  variablesArray+=( "" )
  variablesArray+=( "" )
  variablesArray+=( "run_type=$run_type" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -r/--run_type" )
  variablesArray+=( "  desc: what operation to perform, valid options are help and run" )
  variablesArray+=( "" )
  variablesArray+=( "interactive=$interactive" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -y/--interactive" )
  variablesArray+=( "  desc: flag, allow user interaction, should always be false running on docker" )
  variablesArray+=( "  note: non-interactive=0 interactive=1, if used as a parameter set to 1" )
  variablesArray+=( "" )
  variablesArray+=( "verbose=$verbose" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -v/--verbose" )
  variablesArray+=( "  desc: flag, the verbosity level to use, this can be used parameter multiple times" )
  variablesArray+=( "    example: -v -v gives you verbosity level 2" )
  variablesArray+=( "    levels:" )
  variablesArray+=( "      0: minimal, only what needs to be shown and errors" )
  variablesArray+=( "      1: info, basic info (recommended)" )
  variablesArray+=( "      2: debug, all logs" )
  variablesArray+=( "" )
  variablesArray+=( "skip_update=$skip_update" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -ud/--skip_update" )
  variablesArray+=( "  desc: flag, skip apt-get update" )
  variablesArray+=( "  note: update=0 skip update=1, if used as a parameter set to 1" )
  variablesArray+=( "" )
  variablesArray+=( "skip_upgrade=$skip_upgrade" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -ug/--skip_upgrade" )
  variablesArray+=( "  desc: flag, skip apt-get upgrade" )
  variablesArray+=( "  note: upgrade=0 skip upgrade=1, if used as a parameter set to 1" )
  variablesArray+=( "" )
  variablesArray+=( "skip_autoremove=$skip_autoremove" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -ar/--skip_autoremove" )
  variablesArray+=( "  desc: flag, skip apt-get autoremove" )
  variablesArray+=( "  note: autoremove=0 skip autoremove=1, if used as a parameter set to 1" )
  variablesArray+=( "" )
  variablesArray+=( "myserver_country=$myserver_country" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -msc/--myserver_country" )
  variablesArray+=( "  desc: string for myserver.cnf, country, 2 or 3 letters, default US" )
  variablesArray+=( "" )
  variablesArray+=( "myserver_state=$myserver_state" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -mss/--myserver_state" )
  variablesArray+=( "  desc: string for myserver.cnf, state, 2 or 3 letters, default UT" )
  variablesArray+=( "" )
  variablesArray+=( "myserver_location=$myserver_location" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -msl/--myserver_location" )
  variablesArray+=( "  desc: string for myserver.cnf, location, any amount of letters, default SLC" )
  variablesArray+=( "" )
  variablesArray+=( "myserver_organizational_unit=$myserver_organizational_unit" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -msou/--myserver_organizational_unit" )
  variablesArray+=( "  desc: string for myserver.cnf, organizational unit, any amount of letters, default IT" )
  variablesArray+=( "" )
  variablesArray+=( "myserver_fully_qualified_domain_name=$myserver_fully_qualified_domain_name" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -msfqdn/--myserver_fully_qualified_domain_name" )
  variablesArray+=( "  desc: string for myserver.cnf, fully qualified domain name, [a-zA-Z0-9._-]+ , default k3s.local" )
  variablesArray+=( "" )
  variablesArray+=( "myserver_organization_name=$myserver_organization_name" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -mson/--myserver_organization_name" )
  variablesArray+=( "  desc: string for myserver.cnf, organization name, any amount of letters, default k3s" )
  variablesArray+=( "" )
  variablesArray+=( "skip_del_pi_user=$skip_del_pi_user" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -sdpu/--skip_del_pi_user" )
  variablesArray+=( "  desc: flag, skip deleting the pi user" )
  variablesArray+=( "  note: delete pi user=0 skip delete pi user=1, if used as a parameter set to 1" )
  variablesArray+=( "" )
  variablesArray+=( "skip_deny_ssh_passwords=$skip_deny_ssh_passwords" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -sdsp/--skip_deny_ssh_passwords" )
  variablesArray+=( "  desc: flag, skip denying the use of ssh with passwords" )
  variablesArray+=( "  note: no ssh passwords=0 allow ssh passwords=1, if used as a parameter set to 1" )
  variablesArray+=( "" )
  variablesArray+=( "context_name=$context_name" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -cn/--context_name" )
  variablesArray+=( "  desc: the name of the context to use for the kubeconfig, default value is default" )
  variablesArray+=( "" )
  variablesArray+=( "ssh_port=$ssh_port" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -sp/--ssh_port" )
  variablesArray+=( "  desc: the port to use for ssh, default value is 22" )
  variablesArray+=( "" )
  variablesArray+=( "cluster_ssh_port=$cluster_ssh_port" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -csp/--cluster_ssh_port" )
  variablesArray+=( "  desc: the port to use for ssh for the cluster, default value is 22" )
  variablesArray+=( "" )
  variablesArray+=( "initial_target_username=$initial_target_username" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -itu/--initial_target_username" )
  variablesArray+=( "  desc: the initial username for the target, default value is pi" )
  variablesArray+=( "" )
  variablesArray+=( "initial_target_password=$initial_target_password" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -itp/--initial_target_password" )
  variablesArray+=( "  desc: the initial password for the target, default value is raspberry" )
  variablesArray+=( "" )
  variablesArray+=( "cluster_username=$cluster_username" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -cu/--cluster_username" )
  variablesArray+=( "  desc: the username to use for the cluster, default value \$cluster_username=\"\$username (${username})" )
  variablesArray+=( "" )
  variablesArray+=( "always_use_key=$always_use_key" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -sdsp/--always_use_key" )
  variablesArray+=( "  desc: flag, only use ssh keys" )
  variablesArray+=( "  note: use initial username and password=0 only use ssh keys=1, if used as a parameter set to 1" )
  variablesArray+=( "" )
  variablesArray+=( "install_as_cluster=$install_as_cluster" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -iac/--install_as_cluster" )
  variablesArray+=( "  desc: flag, install as cluster" )
  variablesArray+=( "  note: don't install as cluster=0 install as cluster=1, if used as a parameter set to 1" )
  variablesArray+=( "" )
  variablesArray+=( "join_as_server=$join_as_server" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -jas/--join_as_server" )
  variablesArray+=( "  desc: flag, join as server" )
  variablesArray+=( "  note: don't join as server=0 join as server=1, if used as a parameter set to 1" )
  variablesArray+=( "" )
  variablesArray+=( "final_reboot=$final_reboot" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -fr/--final_reboot" )
  variablesArray+=( "  desc: flag, reboot target after run" )
  variablesArray+=( "  note: don't reboot=0 reboot=1, if used as a parameter set to 1" )
  variablesArray+=( "" )
  variablesArray+=( "wait_for_final_reboot=$wait_for_final_reboot" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -wfr/--wait_for_final_reboot" )
  variablesArray+=( "  desc: flag, wait for the target to come back up after final reboot" )
  variablesArray+=( "  note: don't wait for reboot=0 wait for reboot=1, if used as a parameter set to 1" )
  variablesArray+=( "" )

  write_block 1 "${variablesArray[@]}"
  write_block 2 "" "contents of /etc/resolv.conf" "" "$(cat /etc/resolv.conf)"
}

validate_variables() {
  host "$hostname" 2>&1 > /dev/null
  if [ ! $? -eq 0 ]; then
    die "ERROR: \$hostname \"$hostname\" is not a valid hostname, please run with -h"
  fi

  if ! is_valid_username "$username"; then
    die "ERROR: \$username \"$username\" is not a valid username, please run with -h"
  fi

  if [[ ! "$password" =~ ^.+$ ]]; then
    die "ERROR: \$password \"***\" is not valid, please run with -h"
  fi

  if [ ! -z "$cluster_server_name" ]; then
    host "$cluster_server_name" 2>&1 > /dev/null
    if [ ! $? -eq 0 ]; then
      die "ERROR: \$cluster_server_name \"$cluster_server_name\" is not a valid hostname, please run with -h"
    fi
  fi

  write_block 2 "assume valid \$id_rsa_pub_location"

  if ! is_valid_username "$admin_username"; then
    die "ERROR: \$admin_username \"$admin_username\" is not a valid username, please run with -h"
  fi

  if [[ ! "$admin_ssh_password" =~ ^.+$ ]]; then
    die "ERROR: \$admin_ssh_password \"***\" is not valid, please run with -h"
  fi

  if [[ ! "$run_type" =~ ^(help|run)$ ]]; then
    die "ERROR: \$run_type \"$run_type\" is not valid, please run with -h"
  fi

  if [[ ! "$verbose" =~ ^[0-9]+$ ]]; then
    die "ERROR: \$verbose \"$verbose\" is not valid, please run with -h"
  fi

  if [ ! -z "$interactive" ]; then
    if [[ ! "$interactive" =~ ^[0-1]$ ]]; then
      die "ERROR: \$interactive \"$interactive\" is not valid, please run with -h"
    fi
  fi

  if [[ ! "$skip_update" =~ ^[0-1]$ ]]; then
    die "ERROR: \$skip_update \"$skip_update\" is not valid, please run with -h"
  fi

  if [[ ! "$skip_upgrade" =~ ^[0-1]$ ]]; then
    die "ERROR: \$skip_upgrade \"$skip_upgrade\" is not valid, please run with -h"
  fi

  if [[ ! "$skip_autoremove" =~ ^[0-1]$ ]]; then
    die "ERROR: \$skip_autoremove \"$skip_autoremove\" is not valid, please run with -h"
  fi

  if [[ ! "$myserver_country" =~ ^[a-zA-z]{2,3}$ ]]; then
    die "ERROR: \$myserver_country \"$myserver_country\" is not valid, please run with -h"
  fi

  if [[ ! "$myserver_state" =~ ^[a-zA-z]{2,3}$ ]]; then
    die "ERROR: \$myserver_state \"$myserver_state\" is not valid, please run with -h"
  fi

  if [[ ! "$myserver_location" =~ ^[a-zA-z]+$ ]]; then
    die "ERROR: \$myserver_location \"$myserver_location\" is not valid, please run with -h"
  fi

  if [[ ! "$myserver_organizational_unit" =~ ^[a-zA-z]+$ ]]; then
    die "ERROR: \$myserver_organizational_unit \"$myserver_organizational_unit\" is not valid, please run with -h"
  fi

  if [[ ! "$myserver_fully_qualified_domain_name" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    die "ERROR: \$myserver_fully_qualified_domain_name \"$myserver_fully_qualified_domain_name\" is not valid, please run with -h"
  fi

  if [[ ! "$myserver_organization_name" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    die "ERROR: \$myserver_organization_name \"$myserver_organization_name\" is not valid, please run with -h"
  fi

  if [[ ! "$skip_del_pi_user" =~ ^[0-1]$ ]]; then
    die "ERROR: \$skip_del_pi_user \"$skip_del_pi_user\" is not valid, please run with -h"
  fi

  if [[ ! "$skip_deny_ssh_passwords" =~ ^[0-1]$ ]]; then
    die "ERROR: \$skip_deny_ssh_passwords \"$skip_deny_ssh_passwords\" is not valid, please run with -h"
  fi

  if [[ ! "$context_name" =~ ^.+$ ]]; then
    die "ERROR: \$context_name \"$context_name\" is not valid, please run with -h"
  fi

  if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then
    if [ $ssh_port -lt 0 ] || [ $ssh_port -gt 65535 ]; then
      die "ERROR: \$ssh_port \"$ssh_port\" is not a valid port, please run with -h"
    fi
  else
    die "ERROR: \$ssh_port \"$ssh_port\" is not a valid port, please run with -h"
  fi

  if [[ "$cluster_ssh_port" =~ ^[0-9]+$ ]]; then
    if [ $cluster_ssh_port -lt 1 ] || [ $cluster_ssh_port -gt 65535 ]; then
      die "ERROR: \$cluster_ssh_port \"$cluster_ssh_port\" is not a valid port, please run with -h"
    fi
  else
    die "ERROR: \$cluster_ssh_port \"$cluster_ssh_port\" is not a valid port, please run with -h"
  fi

  if ! is_valid_username "$initial_target_username"; then
    die "ERROR: \$initial_target_username \"$initial_target_username\" is not a valid username, please run with -h"
  fi

  if [[ ! "$initial_target_password" =~ ^.+$ ]]; then
    die "ERROR: \$initial_target_password \"***\" is not valid, please run with -h"
  fi

  if ! is_valid_username "$cluster_username"; then
    die "ERROR: \$cluster_username \"$cluster_username\" is not a valid username, please run with -h"
  fi

  if [[ ! "$always_use_key" =~ ^[0-1]$ ]]; then
    die "ERROR: \$always_use_key \"$always_use_key\" is not valid, please run with -h"
  fi

  if [[ ! "$install_as_cluster" =~ ^[0-1]$ ]]; then
    die "ERROR: \$install_as_cluster \"$install_as_cluster\" is not valid, please run with -h"
  fi

  if [[ ! "$join_as_server" =~ ^[0-1]$ ]]; then
    die "ERROR: \$join_as_server \"$join_as_server\" is not valid, please run with -h"
  fi

  if [[ ! "$final_reboot" =~ ^[0-1]$ ]]; then
    die "ERROR: \$final_reboot \"$final_reboot\" is not valid, please run with -h"
  fi

  if [[ ! "$wait_for_final_reboot" =~ ^[0-1]$ ]]; then
    die "ERROR: \$wait_for_final_reboot \"$wait_for_final_reboot\" is not valid, please run with -h"
  fi
}

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
