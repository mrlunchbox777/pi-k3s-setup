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
for pi_k3s_setup_lib_f in $(ls -p "$pi_k3s_base_dir/lib/" | grep -v /); do
  source "$pi_k3s_base_dir/lib/$pi_k3s_setup_lib_f";
done

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
