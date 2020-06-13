#!/bin/bash

# Install libvirt, KVM & Vagrant
sudo apt-get update && sudo apt-get install -y bridge-utils dnsmasq-base ebtables libvirt-bin libvirt-dev qemu-kvm qemu-utils ruby-dev
sudo wget -nv https://releases.hashicorp.com/vagrant/2.2.7/vagrant_2.2.7_x86_64.deb
sudo dpkg -i vagrant_2.2.7_x86_64.deb
vagrant --version
sudo vagrant plugin install vagrant-libvirt

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR

sudo vagrant up --provider=libvirt
sudo vagrant ssh -c "cd dswg && sudo /usr/bin/go test -v"
