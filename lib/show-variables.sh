# When updating this ensure to update valiadate-variables.sh
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
