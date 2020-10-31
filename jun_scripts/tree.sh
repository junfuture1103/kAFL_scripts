#!/bin/sh

while :
do
        cd ~/kAFL/out/corpus
        tree
        echo "\n ==========  Here is crash ==========  \n"

        cd crash
        cat *
        echo "\n"

        echo "\n ==========  Here is regular ==========  \n"
        cd ~/kAFL/out/corpus/regular

        cat *
        echo "\n"

        sleep 3

done
