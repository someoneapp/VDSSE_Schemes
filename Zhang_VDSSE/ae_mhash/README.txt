Notes
=====

The files in this archive are the ones used to produce the results in the paper "The Software Performance of Authenticated-Encryption Modes" presented at FSE 2011. The sole purpose of this archive is to allow readers to verify those results. For the latest OCB implementations, better suited for use in new projects, see http://www.cs.ucdavis.edu/~rogaway/ocb/.

- I found that on some multiple cpu machines, I would get irregular timing results, presumably because processes were migrating between cpus. These strange results went away when I made linux see just a single processor.

In the bios, turn off hyperthreading and any speed scaling technologies.

In linux

  echo 0 >> /sys/devices/system/cpu/cpu1/online

turns off cpu1. Do this for each processor you want off.


- When OpenSSL libraries were needed, I'd do like:

wget ftp://ftp.openssl.org/snapshot/openssl-SNAP-20100714.tar.gz
./config -march=native
make install

then compile like

gcc -static foo.c -I/usr/local/ssl/include -L/usr/local/ssl/lib64 -lcrypto

or

gcc -static foo.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto

(You may need to append -ldl in some compiles, or change -march=native to a different -mcpu or -march setting.)
