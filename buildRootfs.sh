#!/bin/bash

# This script prepare the an ubuntu rootfs
sudo apt-get install debootstrap
sudo debootstrap --arch i386 xenial ./rootfs http://archive.ubuntu.com/ubuntu
