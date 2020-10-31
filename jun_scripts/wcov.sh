#!/bin/sh
cd ~/kAFL/
python3 kAFL-Fuzzer/kafl_cov.py \
	-vm_ram snapshot_win/ \
	-vm_dir snapshot_win/ \
	-agent targets/windows_x86_64/bin/fuzzer/hprintf_test.exe \
	-mem 4096 \
	-seed_dir in/ \
	-work_dir out/ \
	-ip0 0xfffff80217240000-0xfffff80217247000 \
	-p 2 \
	-forkserver \
	-d \
	-v \
	--purge
