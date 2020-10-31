#!/bin/sh

while :
do
	
	echo "--------slave_stats_0--------\n"
	./tools/mcat.py out/slave_stats_0

	echo "--------slave_stats_1--------\n"
	./tools/mcat.py out/slave_stats_1

	echo "--------slave_stats_2--------\n"
	./tools/mcat.py out/slave_stats_2

	echo "--------slave_stats_3--------\n"
	./tools/mcat.py out/slave_stats_3
	
	echo "\n------ If you want to exit, please enter Ctrl+C ------\n"

	sleep 2
done




