#!/bin/bash
date=`date +%F_%k:%M:`
hostname=`hostname`

# -i0 -i1 for test 0 and 1 (write and read)
# -r 4 for 4 KB records
# -s 100M  for 100M files for each thread, so 1000M ~ 1G total
# -t 10 for 10 threads 
# -R for excel
# -b for filename


sync=100
coe2=100
reqsize=512
filesize=256*2
delay=0
i=3
#run infinitely, incrementing i on each interaction
sudo sync && echo 3 | sudo  tee /proc/sys/vm/drop_caches
 
 ./iozone -w -J $[ delay ] -+T -i1 -I -r $[ reqsize ]K  -s $[ filesize ]M -t 1  -F ./tmp_10G_$i >  iozone_sync$[ sync ]_delay$[ delay ]_user$[ i ].log  &
p3=$!
echo $p3 | sudo tee /sys/fs/cgroup/blkio/user_3/cgroup.procs
let i=i-1

 ./iozone -w -J $[ delay ] -+T -i1 -I -r $[ reqsize ]K  -s $[ filesize ]M -t 1  -F ./tmp_10G_$i >  iozone_sync$[ sync ]_delay$[ delay ]_user$[ i ].log  &
p2=$!
echo $p2 | sudo tee /sys/fs/cgroup/blkio/user_2/cgroup.procs
let i=i-1

 ./iozone -w -J $[ delay ] -+T -i1 -I -r $[ reqsize ]K  -s $[ filesize ]M -t 1  -F ./tmp_10G_$i >  iozone_sync$[ sync ]_delay$[ delay ]_user$[ i ].log  &
p1=$!
echo $p1 | sudo tee /sys/fs/cgroup/blkio/user_1/cgroup.procs
let i=i-1


sudo iotop -u cass2014 -P -d 2 -t >  iotop_sync$[ sync ]_delay$[ delay ]_$[ reqsize ]K.log &
io=$!
wait $p1
sleep 3
sudo kill -9 $io
killall -s 9 iozone
sleep 3





echo finish
