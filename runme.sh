#!/bin/bash

# * &&& Write out safe variables and verify go &&&&
if [ ! -z "${id_rsa_pub_location}" ]
then
    ssh-keygen -f /home/${admin_username}/.ssh/id_rsa -N "${admin_ssh_password}"
    export id_rsa_pub_location="/home/${admin_username}/.ssh/id_rsa.pub"
fi
echo -n "${admin_ssh_password}" | ssh-add -p "${id_rsa_pub_location}"
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

echo "Waiting 5 seconds for reboot..."
sleep 5
if [ -z /usr/local/bin/k3sup ]
then
    echo "Installing k3s"
    curl -sLS https://get.k3sup.dev | sh
    sudo install k3sup /usr/local/bin/
fi
k3sup install --host ${hostname} --user ${username} --ssh-key ${id_rsa_pub_location} --cluster
if [ ! -z "${cluster_server_ip}" ]
then
    k3sup join --host ${hostname} --user ${username} --server-host ${hostname} --server-user ${username} --ssh-key ${id_rsa_pub_location} --server
fi
