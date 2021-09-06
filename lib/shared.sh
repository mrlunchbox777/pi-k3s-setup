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
  instructionArray+=( "      2. The subfolder .kube in .docker-data will have config data" )
  instructionArray+=( "  b. Host" )
  instructionArray+=( "    i. You will find all data in the following folders after running" )
  instructionArray+=( "      1. The folder at \$id_rsa_pub_location (${id_rsa_pub_location}) will have all of the ssh data" )
  instructionArray+=( "      2. The folder /.kube will have config data" )
  instructionArray+=( "" )

  write_block 1 "${instructionArray[@]}"
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

post_run() {
  write_block 1 "Successful Run"
  show_variables
  postRunArray=( "" )
  postRunArray+=( "Successful Run" )
  postRunArray+=( "For the security conscious consider changing the following:" )
  postRunArray+=( "  - password on the target" )
  postRunArray+=( "  - the password for the sshkey" )
  postRunArray+=( "If running from docker you will find your ssh keys and .kube/config in the .docker-data folder" )

  postRunArray+=( "" )
  write_block 1 "${postRunArray[@]}"
}
