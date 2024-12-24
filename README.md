# AES-Driver

1. build: make hoac make all
2. check module info
modinfo <file_name.ko>
3. load module
sudo insmod <file_name.ko>
//load va execute kernel module
sudo insmod ./file_name.ko
4. monitor the operation process of module
dmesg
6. remove module 
sudo rmmod <file_name>
