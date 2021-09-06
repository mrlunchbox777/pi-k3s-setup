# When updating this ensure to update show-variables.sh
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

  host "$initial_target_hostname" 2>&1 > /dev/null
  if [ ! $? -eq 0 ]; then
    die "ERROR: \$initial_target_hostname \"$initial_target_hostname\" is not a valid hostname, please run with -h"
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
