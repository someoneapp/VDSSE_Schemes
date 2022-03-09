#!/bin/bash
for i in {1..10} 
do
rm -rf /tmp/my*
kill -9 $(pgrep server)
./server /tmp/my.sdb &
./client /tmp/my.cdb 1 32768 inverted-index.txt
done


for i in {1..10} 
do
rm -rf /tmp/my*
kill -9 $(pgrep server)
./server /tmp/my.sdb &
./client /tmp/my.cdb 1 65536 inverted-index.txt
done

for i in {1..10} 
do
rm -rf /tmp/my*
kill -9 $(pgrep server)
./server /tmp/my.sdb &
./client /tmp/my.cdb 1 131072 inverted-index.txt
done

for i in {1..10} 
do
rm -rf /tmp/my*
kill -9 $(pgrep server)
./server /tmp/my.sdb &
./client /tmp/my.cdb 1 262144 inverted-index.txt
done

for i in {1..10} 
do
rm -rf /tmp/my*
kill -9 $(pgrep server)
./server /tmp/my.sdb &
./client /tmp/my.cdb 1 524288 inverted-index.txt
done

for i in {1..10} 
do
rm -rf /tmp/my*
kill -9 $(pgrep server)
./server /tmp/my.sdb &
./client /tmp/my.cdb 1 1048576 inverted-index.txt
done

for i in {1..10} 
do
rm -rf /tmp/my*
kill -9 $(pgrep server)
./server /tmp/my.sdb &
./client /tmp/my.cdb 1 2097152 inverted-index.txt
done

for i in {1..10} 
do
rm -rf /tmp/my*
kill -9 $(pgrep server)
./server /tmp/my.sdb &
./client /tmp/my.cdb 1 4194304 inverted-index.txt
done

for i in {1..10} 
do
rm -rf /tmp/my*
kill -9 $(pgrep server)
./server /tmp/my.sdb &
./client /tmp/my.cdb 1 8388608  inverted-index.txt
done
