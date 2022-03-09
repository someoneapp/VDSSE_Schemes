#!/bin/bash

./client /tmp/my.cdb 1 8388608 inverted-index.txt

if [ $1 = "1" ] ; then
./client /tmp/my.cdb 4 del.txt
echo "del 1%"
elif [ $1 = "10" ] ; then  
./client /tmp/my.cdb 4 del10.txt
echo "del 10%"
elif [ $1 = "30" ] ; then
./client /tmp/my.cdb 4 del30.txt
echo "del 30%"
elif [ $1 = "50" ] ; then
./client /tmp/my.cdb 4 del50.txt
echo "del 50%"
else
echo "del 0%"
fi     #ifend


./client /tmp/my.cdb 3 spaceman
./client /tmp/my.cdb 3 artifact
./client /tmp/my.cdb 3 ethnic
./client /tmp/my.cdb 3 europe
./client /tmp/my.cdb 3 american
./client /tmp/my.cdb 3 cheers

#after renewing proof
./client /tmp/my.cdb 3 spaceman
./client /tmp/my.cdb 3 artifact
./client /tmp/my.cdb 3 ethnic
./client /tmp/my.cdb 3 europe
./client /tmp/my.cdb 3 american
./client /tmp/my.cdb 3 cheers
