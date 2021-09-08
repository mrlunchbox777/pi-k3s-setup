# pi-k3s-setup

They keys and .kube/config end up in the .docker-data folder. You will need to update the .kube/config to use the right hostname.

## Issues

* No issues creating the cluster at this point, but lots of improvements

## Setup

* On your machine
  * Download raspbian and flash it to SD card
    * [Download image](https://www.raspberrypi.org/software/operating-systems/) & flash using [balena etcher](https://www.balena.io/etcher/)
    * Flash using [Raspberry Pi Imager](https://www.raspberrypi.org/downloads.../)
* On the pi
  * Start up with network, monitor, keyboard, mouse, and SD card
    * Default credentials
      * u: `raspberry`
      * p: `pi`
    * Run `sudo raspi-config`
      * 1-S4: Hostname
        * Change to desired value
      * 3-P2: SSH
        * Enable
      * 4-P2: GPU Memory
        * Change from `64`->`16`
    * Finish & Reboot
      * You can disconnect peripherals from the pi any time you want (could be worth leaving them until it's at least joined your cluster)
* On your machine
  * From the root of this directory run `docker-compose build && docker-compose up`

## Improvements

* update variable names
* split into multiple scripts
* rewrite how the .kube/config gets updated, update the docs and show help as well
* rename runme
* rename repo

## Links

* [Manual Install](https://blog.alexellis.io/test-drive-k3s-on-raspberry-pi/)
* [k3sup](https://github.com/alexellis/k3sup)
