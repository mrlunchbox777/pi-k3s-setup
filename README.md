# pi-k3s-setup

They keys and .kube/config end up in the .docker-data folder. You will need to update the .kube/config to use the right hostname.

## Issues

* No issues creating the cluster at this point, but lots of improvements

## Setup

### Raspberry Pi

[Raspberry Pi Page](https://www.raspberrypi.org/)

* On your machine
  * Download raspbian and flash it to SD card using one of:
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
  * `cd` to the root of this directory
  * Run `cp template.env .env`
  * Customize your `.env`
  * Run `docker-compose build && docker-compose up`

### Jetson Nano

[Jetson Nano Page](https://www.nvidia.com/en-us/autonomous-machines/embedded-systems/jetson-nano/)

* On your machine
  * Download jetpack and flash it to SD card
    * [Download image](https://developer.nvidia.com/jetson-nano-sd-card-image)
    * Flash using [balena etcher](https://www.balena.io/etcher/)
* On the pi
  * Start up with network, monitor, keyboard, mouse, and SD card
    * Follow setup instructions and set credentials
      * The SSH server is setup by default and will allow that user to remote in
    * Finish & Reboot
      * You can disconnect peripherals from the pi any time you want (could be worth leaving them until it's at least joined your cluster)
* On your machine
  * `cd` to the root of this directory
  * Run `cp template.env .env`
  * Customize your `.env`
  * Run `docker-compose build && docker-compose up`

## Links

* [Manual Install](https://blog.alexellis.io/test-drive-k3s-on-raspberry-pi/)
* [k3sup](https://github.com/alexellis/k3sup)
