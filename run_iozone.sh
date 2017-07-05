#!/bin/bash
date=`date +%F_%k:%M:`
hostname=`hostname`

if [ ! $# -gt 1 ]; then
    echo $0: usage: "
			-g|cgroups (number of control groups to run)"
    exit 1
fi

# -i0 -i1 for test 0 and 1 (write and read)
# -r 4 for 4 KB records
# -s 100M  for 100M files for each thread, so 1000M ~ 1G total
# -t 10 for 10 threads 
# -R for excel
# -b for filename


#test 1: time slice is varied from 100 to 400ms
#test 2: time slice is a constant (200ms) 
sync=100
coe3=100
python cat_cgroup_io.py
while [ $sync -le 400 ]
do
echo $sync | sudo tee /sys/block/sda/queue/iosched/slice_sync

#test 1: time idle is a constant (8ms)
#test 2: time idle is varied from 0 to 128ms
idle=8
coe2=8
while [ $idle -le 8 ]
do 
echo $idle | sudo tee /sys/block/sda/queue/iosched/slice_idle

#test 1: request interval is varied from 0 to 32ms
#test 2: request interval is varied from 0 to 128ms
delay=0
coe=1
while [ $delay -le 32 ]
do
i=$2

#run infinitely, incrementing i on each interaction
sudo sync && echo 3 | sudo  tee /proc/sys/vm/drop_caches
while [ $i -ge 1 ]
do 
 echo "iozone -w -J $delay -+T -i1 -I -r 512K  -s $[ 512*4 ]M -t 1  -F ./result1/tmp_10G_$i >  ./result1/iozone_sync$[ sync ]_idle$[ idle ]_delay$[ delay ]_user$[ i ].log  &"
 iozone -w -J $delay -+T -i1 -I -r 512K  -s $[ 512*4 ]M -t 1  -F ./result1/tmp_10G_$i >  ./result1/iozone_sync$[ sync ]_idle$[ idle ]_delay$[ delay ]_user$[ i ].log  &
pi=$!
echo $pi | sudo tee /sys/fs/cgroup/blkio/user_$i/cgroup.procs

  let i=i-1
done

iostat -x  2 sda >  ./result1/iostat_sync$sync$idle$delay.log &
io=$!
wait $pi
kill -9 $io
killall -s 9 iozone
sleep 3
let coe=coe*2
let delay=coe
done

let coe2=coe2*2
let idle=coe2
sleep 3
done

let coe3=coe3*2
let sync=coe3
sleep 3
done

python cat_cgroup_io.py

echo finish
