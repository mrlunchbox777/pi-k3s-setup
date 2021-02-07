# pi-k3s-setup

## Host run emaples

* `./runme.sh -hn "test" -u "test2" -p "test3" -c "test4" -i "test5" -a "test6" -s "test7" -r "test8" -y`
* `./runme.sh --hostname "test" --username "test2" --password "test3" --cluster_server_ip "test4" --id_rsa_pub_location "test5" --admin_username "test6" --admin_ssh_password "test7" --run_type "test8" --interactive`
* `./runme.sh --hostname="test" --username="test2" --password="test3" --cluster_server_ip="test4" --id_rsa_pub_location="test5" --admin_username="test6" --admin_ssh_password="test7" --run_type="test8" --interactive`

# Bad Host runs
* `./runme.sh --hostname="" --username="" --password="" --cluster_server_ip="" --id_rsa_pub_location="" --admin_username="" --admin_ssh_password="" --run_type=""`
* `./runme.sh -hn "" -u "" -p "" -c "" -i "" -a "" -s "" -r ""`
