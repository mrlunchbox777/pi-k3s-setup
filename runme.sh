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
delimiter="*******************************************************"
force_help=0

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
    die "An error occurred during $2. Check logs for more detail."
  fi
}

is_valid_username() {
  local re='^[[:lower:]_][[:lower:][:digit:]_-]{2,15}$'
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
  instructionArray+=( "" )

  write_block 1 "${instructionArray[@]}"
}

show_variables() {
  local masked_password=$(echo -e $password | sed "s#1/#\*/#")
  local masked_ssh_password=$(echo -e $admin_ssh_password | sed "s#1/#\*/#")

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
  variablesArray+=( "  note: if left empty it will create an id_rsa at /home/\${admin_username}/.ssh/id_rsa.pub" )
  variablesArray+=( "" )
  variablesArray+=( "admin_username=$admin_username" )
  variablesArray+=( "  required" )
  variablesArray+=( "  -a/--admin_username" )
  variablesArray+=( "  desc: the username to use on the Admin Machine" )
  variablesArray+=( "" )
  variablesArray+=( "admin_ssh_password=$masked_ssh_password" )
  variablesArray+=( "  optional" )
  variablesArray+=( "  -s/--admin_ssh_password" )
  variablesArray+=( "  desc: the password to use for the id_rsa in \${id_rsa_pub_location}" )
  variablesArray+=( "  note: if left empty no password will be used (not recommended)" )
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
  variablesArray+=( "  note: non-interactive=0 interactive=1" )
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

  write_block 0 "${variablesArray[@]}"
  write_block 2 "" "contents of /etc/resolv.conf" "" "$(cat /etc/resolv.conf)"
}

validate_variables() {
  host "$hostname" 2>&1 > /dev/null
  if [ ! $? -eq 0 ]; then
    die 'ERROR: "$hostname" is not a valid hostname, please run with -h'
  fi

  if ! is_valid_username "$username"; then
    die 'ERROR: "$username" is not a valid username, please run with -h'
  fi

  write_block 2 "assume valid \$password"

  if [ ! -z "$cluster_server_name" ]; then
    host "$cluster_server_name" 2>&1 > /dev/null
    if [ ! $? -eq 0 ]; then
      die 'ERROR: "$cluster_server_name" is not a valid hostname, please run with -h'
    fi
  fi

  write_block 2 "assume valid \$id_rsa_pub_location"

  if ! is_valid_username "$admin_username"; then
    die 'ERROR: "$admin_username" is not a valid username, please run with -h'
  fi

  write_block 2 "assume valid \$admin_ssh_password"

  if [[ ! "$run_type" =~ ^(help|run)$ ]]; then
    die 'ERROR: "$run_type" is not valid, please run with -h'
  fi

  if [[ ! "$verbose" =~ ^[0-9]+$ ]]; then
    die 'ERROR: "$verbose" is not valid, please run with -h'
  fi

  if [ ! -z "$interactive" ]; then
    if [[ ! "$interactive" =~ ^[0-1]+$ ]]; then
      die 'ERROR: "$interactive" is not valid, please run with -h'
    fi
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

setup_target() {
  most_recent_command_value=0

  if [ -f "/tmp/known_hosts" ]; then
    rm /tmp/known_hosts
  fi

  write_block 2 "add fingerprint to known_hosts"
  # TODO extra output here
  local host_fingerprint_output=$(sshpass -p raspberry ssh -o "UserKnownHostsFile /tmp/known_hosts" -o "StrictHostKeyChecking=accept-new" pi@${hostname} "echo got fingerprint")
  most_recent_command_value=$?
  write_block 2 "$host_fingerprint_output"
  check_for_error $most_recent_command_value "target setup" "add fingerprint to known_hosts"

  write_block 2 "prep the cert"
  if [ ! -z "${id_rsa_pub_location}" ]; then
    id_rsa_pub_location="/home/${admin_username}/.ssh/"
  fi
  if [ ! -f "${id_rsa_pub_location}" ]; then
    mkdir -p "${id_rsa_pub_location}"
  fi
  if [ ! -f "${id_rsa_pub_location}id_rsa" ]; then
    if [ -z "${admin_ssh_password}" ]; then
      write_block 2 "Creating id_rsa without password..."
      local keygen_output=$(ssh-keygen -f "${id_rsa_pub_location}id_rsa" -N "")
      most_recent_command_value=$?
      write_block 2 "$keygen_output"
      check_for_error $most_recent_command_value "target setup" "ssh-keygen without password"
    else
      local keygen_output=$(ssh-keygen -f "${id_rsa_pub_location}id_rsa" -N "${admin_ssh_password}")
      most_recent_command_value=$?
      write_block 2 "$keygen_output"
      check_for_error $most_recent_command_value "target setup" "ssh-keygen with password"
    fi
  fi

  write_block 2 "moving the keys out for password auth"
  mv "${id_rsa_pub_location}id_rsa.pub" "${id_rsa_pub_location}id_rsa.tmp.pub"
  mv "${id_rsa_pub_location}id_rsa" "${id_rsa_pub_location}id_rsa.tmp"

  write_block 2 "copy the public key to the target"
  # TODO extra output here
  local scp_output=$(sshpass -p raspberry scp -o "UserKnownHostsFile /tmp/known_hosts" "${id_rsa_pub_location}id_rsa.tmp.pub" pi@${hostname}:/tmp/id_rsa.pub)
  most_recent_command_value=$?
  write_block 2 "scp_output - $scp_output"
  check_for_error $most_recent_command_value "target setup" "scp"

  sshpass -p raspberry ssh -o "UserKnownHostsFile /tmp/known_hosts" pi@${hostname} " \
    user=$(cat /etc/passwd | egrep -e ansible | awk -F \":\" '{ print $1}'))
    if [[ \"\$user\" != \"${username}\" ]]; then \
      echo -e raspberry | sudo -S useradd -m -G sudo ${username} \
      && echo -e \"${password}\" | passwd ${username}; \
    fi; \
    echo -e raspberry | sudo -S sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config; \
    cat /tmp/id_rsa.pub >> /home/${username}/.ssh/authorized_keys; \
    rm /tmp/id_rsa.pub; \
    echo -e raspberry | sudo -S chown ${username}:$username /home/${username}/.ssh/authorized_keys; \
    echo -e raspberry | sudo -S chmod 755 /home/${username}/.ssh/authorized_keys; \
    echo -e raspberry | sudo -S service ssh restart; \
  "
  most_recent_command_value=$?
  check_for_error $most_recent_command_value "target setup" "ssh block #1"

  write_block 2 "moving the keys out for password auth"
  mv "${id_rsa_pub_location}id_rsa.tmp.pub" "${id_rsa_pub_location}id_rsa.pub"
  mv "${id_rsa_pub_location}id_rsa.tmp" "${id_rsa_pub_location}id_rsa"

  write_block 2 "set up use of the cert"
  # TODO extra output here
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

  ssh ${username}@${hostname} -o "UserKnownHostsFile /tmp/known_hosts" -i "${id_rsa_pub_location}id_rsa" " \
    if [ $(id -u pi) ] \
    then \
      echo -e \"${password}\" | sudo -S userdel -r pi; \
    fi \
    case \`grep -Fx \"$FILENAME\" \"$LIST\" >/dev/null; echo \$?\` in \
      0) \
        echo \"/boot/cmdline.txt already updated\" \
        ;; \
      1) \
        echo -n \" cgroup_enable=cpuset cgroup_memory=1 cgroup_enable=memory \" >> /boot/cmdline.txt; \
        ;; \
      *) \
        echo \"an error occurred, check logs for details\" \
        exit 1 \
        ;; \
    esac \
    echo -e \"${password}\" | sudo -S apt-get update; \
    echo -e \"${password}\" | sudo -S apt-get upgrade -y; \
    echo -e \"${password}\" | sudo -S apt-get autoremove -y; \
    sudo reboot now; \
  "
  most_recent_command_value=$?
  check_for_error $most_recent_command_value "target setup" "ssh block #2"

  write_block 2 "Waiting 5 seconds for reboot..."
  sleep 5

  if [ -z /usr/local/bin/k3sup ]; then
    write_block 2 "Installing k3s"
    curl -sLS https://get.k3sup.dev | sh
    most_recent_command_value=$?
    check_for_error $most_recent_command_value "target setup" "downloading k3sup"
    sudo install k3sup /usr/local/bin/
    most_recent_command_value=$?
    check_for_error $most_recent_command_value "target setup" "installing k3sup"
  fi

  k3sup install --host ${hostname} --user ${username} --ssh-key "${id_rsa_pub_location}id_rsa" --cluster
  most_recent_command_value=$?
  check_for_error $most_recent_command_value "target setup" "k3sup install"

  if [ ! -z "${cluster_server_name}" ]; then
    k3sup join --host ${hostname} --user ${username} --server-host ${cluster_server_name} --server-user ${username} --ssh-key "${id_rsa_pub_location}id_rsa" --server
    most_recent_command_value=$?
    check_for_error $most_recent_command_value "target setup" "k3sup join"
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

show_variables

if [ $run_type = "run" ]; then
  validate_variables
  confirm_run
  setup_target
  post_run
else
  if [ $verbose -lt 1 ]; then
    verbose=$((verbose + 1))
  fi
  show_help
fi
