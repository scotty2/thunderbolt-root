#!/bin/sh

# this builds off of the HTC released desire hd kernel. (using msm7230_defconfig)

./incrementbuild.pl
make -C /home/swalker/tbolt/ace-QMR-g1e30168 M=/home/swalker/tbolt/wpthis -j2
./embedwpthis.pl
arm-linux-gnueabi-gcc -static -owpthis wpthis-exe.c
