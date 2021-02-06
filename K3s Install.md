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
  * sudo raspi-config
    * 8 Update
    * 3 Interface Options
    * 2 SSH
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

### Script 1

* &&& Write out safe variables and verify go &&&&
* if [ ! -z "${id_rsa_pub_location}" ]; then ssh-keygen -f /home/${admin_username}/.ssh/id_rsa -N admin_ssh_password && export id_rsa_pub_location="/home/${admin_username}/.ssh/id_rsa.pub"; fi
* scp ${id_rsa_pub_location}/id_rsa.pub ${admin_username}@${hostname}:/home/${username}/.ssh/id_rsa.pub
* ssh pi@{hostname} -praspberry
  * echo -e raspberry | sudo -S useradd -m -G sudo ${username}
  * echo -e ${password} | passwd ${username}
  * cp /home/${admin_username}/.ssh/id_rsa /home/${username}/.ssh/authorized_keys
  * &&& set GPU memory split to 16mb without config, or maybe tell the user to after... &&&
  * &&& if manual reboot now and ssh with key &&&
  * &&& echo -n " cgroup_enable=cpuset cgroup_memory=1 cgroup_enable=memory " >> /boot/cmdline.txt &&&
  * sudo reboot now

### Script 2

  * 

### After

* &&& mention basically done &&&&
* &&& update sshd_config to not allow passwords &&&
* 
* &&& Write out safe variables and notify successful end &&&&
* &&& Suggest that the security conscious change their secrets (password, sshkey, find others) &&&
