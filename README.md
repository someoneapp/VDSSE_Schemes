# build

```bash
$ make clean
$ make
```


## server side
 
```bash
$ ./server /tmp/my.sdb
```

## client side
```bash
# Batch Addition
#input: the location of the client database, the size of the index, the location of the index
./client /tmp/my.cdb 1 8388608 inverted-index.txt

# search + verify
./client /tmp/my.cdb 3 keyword

# Batch Deletion
./client /tmp/my.cdb 4 del-index.txt

# trace simulation
./client /tmp/my.cdb 5
```
