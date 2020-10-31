#!/bin/sh

sed -i '/qemu-5.0.0/c\qemu_kafl_location = '"$HOME"'/kAFL/qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64' ~/kAFL/kAFL-Fuzzer/kafl.ini

mkdir ~/kAFL/snapshot_win
cd ~/kAFL/snapshot_win/

~/kAFL/qemu-5.0.0/qemu-img create -b ~/kAFL/windows.qcow2 \
	-f qcow2 overlay_0.qcow2
~/kAFL/qemu-5.0.0/qemu-img create -f qcow2 ram_0.qcow2 2048 

cd ~/kAFL
mkdir out/
~/kAFL/qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64 \
	-hdb ~/kAFL/snapshot_win/ram_0.qcow2 \
	-hda ~/kAFL/snapshot_win/overlay_0.qcow2 \
	-machine q35 -serial mon:stdio -net none \
	-enable-kvm -m 2048 \
	
