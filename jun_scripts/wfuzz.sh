#!/bin/sh
cd ~/kAFL/
python3 kAFL-Fuzzer/kafl_fuzz.py \
	-vm_ram snapshot_win/ \
	-vm_dir snapshot_win/ \
	-agent targets/windows_x86_64/bin/fuzzer/CGYAGENT.exe \
	-mem 2048 \
	-seed_dir in/ \
	-work_dir out/ \
	-ip0 0xfffff80279710000-0xfffff80279717000 \
	-d \
	-v \
	--purge
