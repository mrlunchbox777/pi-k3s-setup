# K3s Install

* &&& Add a run me &&
* Get The pi accessible
  * Get the boot drive ready, format using the following
    * &&& add more instruction here &&&
    * [balenaEtcher](https://www.balena.io/etcher/)
    * [Rasbian Lite](https://www.raspberrypi.org/software/operating-systems/)
  * boot & login
    * u: pi
    * p: raspberry
  * sudo vi /etc/hostname
    * change to hostname you want
  * sudo raspi-config
    * 8 Update
    * 1 System Options
    * S4 Hostname
      * Set to desired hostname
    * 3 Interface Options
    * 2 SSH
      * Enable SSH
    * 4 Performance Options
    * P2 GPU Memory 
      * Set to 16
  * Reload ssh, choose one of the following
    * sudo service ssh restart
    * sudo reboot now

## From this point on I want to script

### Variables

* hostname
  * on the pi
* username
  * on the pi
* password
  * on the pi
* id_rsa_pub_location
  * on the admin machine
* admin_username
  * on the admin machine
* admin_ssh_password
  * on the admin machine
* cluster_server_ip
  * if set will join, if not it won't

### Script

* &&& Write out safe variables and verify go &&&&
* if [ ! -z "${id_rsa_pub_location}" ]; then ssh-keygen -f /home/${admin_username}/.ssh/id_rsa -N "${admin_ssh_password}" && export id_rsa_pub_location="/home/${admin_username}/.ssh/id_rsa.pub"; fi
* echo -n "${admin_ssh_password} | ssh-add -p "${id_rsa_pub_location}"
* scp ${id_rsa_pub_location}/id_rsa.pub ${admin_username}@${hostname}:/home/${username}/.ssh/authorized_keys
* ssh pi@{hostname} -praspberry
  * echo -e raspberry | sudo -S useradd -m -G sudo ${username}
  * echo -e ${password} | passwd ${username}
  * echo -e raspberry | sudo -S sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  * exit
* ssh ${username}@${hostname} -i "${id_rsa_pub_location}"
  * echo -e ${password} | sudo -S userdel -r pi
  * echo -n " cgroup_enable=cpuset cgroup_memory=1 cgroup_enable=memory " >> /boot/cmdline.txt
  * echo -e ${password} | sudo -S apt-get update
  * echo -e ${password} | sudo -S apt-get upgrade -y
  * echo -e ${password} | sudo -S apt-get autoremove -y
  * sudo reboot now
* echo "Waiting 5 seconds for reboot..."
* sleep 5
* if [ -z /usr/local/bin/k3sup ]; then echo "Installing k3s" curl -sLS https://get.k3sup.dev | sh && sudo install k3sup /usr/local/bin/; fi
* k3sup install --host ${hostname} --user ${username} --ssh-key ${id_rsa_pub_location} --cluster
* if [ ! -z "${cluster_server_ip}" ]; k3sup join --host ${hostname} --user ${username} --server-host ${hostname} --server-user ${username} --ssh-key ${id_rsa_pub_location} --server ; fi

### After

* &&& mention basically done &&&&
* &&& update sshd_config to not allow passwords &&&
* 
* &&& Write out safe variables and notify successful end &&&&
* &&& Suggest that the security conscious change their secrets (password, sshkey, find others) &&&
