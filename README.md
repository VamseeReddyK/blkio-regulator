# blkio-regulator

1. Compile the modified kernel
-------------------------------------------------------------
$ cd ~/linux-4.10.17

$ sudo cp /boot/<any configuration file> .config

$ make bzImage

$ make modules

$ make modules_install

$ sudo cp .config /boot/config-4.10.17

$ sudo cp arch/x86/boot/bzImage /boot/vmlinuz-4.10.17

$ sudo cp System.map /boot/System.map-4.10.17

$ sudo mkinitramfs -o /boot/initramfs-4.10.17 4.10.17

$ sudo update-grub

2. Reboot to the compiled kernel

3. Compile and load block io regulator module
--------------------------------------------------------------
$ cd ~/blkio_regulator_module/KERN_SRC

$ make clean && make

$ sudo insmod blkio_regulator.ko

4. unload the module after testing
---------------------------------------
$ sudo rmmod blkio_regulator
