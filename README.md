# pi-k3s-setup

They keys and kubeconfig end up in the .docker-data folder. You will need to update the kubeconfig to use the right hostname.

## Issues

* No issues creating the cluster at this point, but lots of improvements

## Improvements

* make sure k3s is running at the very end (non-cluster, then join as server, skips start but doesn't fail)
* update variable names
* split into multiple scripts
* rename runme
* rename repo

## Links

* [Manual Install](https://blog.alexellis.io/test-drive-k3s-on-raspberry-pi/)
* [k3sup](https://github.com/alexellis/k3sup)
