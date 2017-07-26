#!/bin/bash

if [ ! $# -gt 1 ]; then
    echo $0: usage: "
			-g|cgroups (number of control groups to run)"
    exit 1
fi
date=`date +%F_%k:%M:`
hostname=`hostname`
fio_output="fio_tests.csv"
iozone_output="iozone_tests.csv"
jobs=$(($2-1))
fio=$4

# -i0 -i1 for test 0 and 1 (write and read)
# -r 4 for 4 KB records
# -s 100M  for 100M files for each thread, so 1000M ~ 1G total
# -t 10 for 10 threads 
# -R for excel
# -b for filename

python cat_cgroup_io.py

if $fio ; then
	echo "Slice_Idle,Group_Idle,Slice_Sync,Request_Interval,Group1(io),Group2(io),Group3(io),Group1(aggrb),Group2(aggrb),Group3(aggrb),Group1(mint),Group2(mint),Group3(mint),Group1(Time),Group2(Time),Group3(Time)" >> $fio_output
else
	echo "Slice_Idle,Group_Idle,Slice_Sync,Request_Interval,Group1(throughput),Group2(throughput),Group3(throughput),Group1(Time spent),Group2(Time spent),Group3(Time spent)" >> $iozone_output
fi

group_idle=8
echo $group_idle | sudo tee /sys/block/sda/queue/iosched/group_idle
slice_idle=0
coe3=1
while [ $slice_idle -le 8 ]
do
	echo $slice_idle | sudo tee /sys/block/sda/queue/iosched/slice_idle
	sync=50
	coe2=50
	while [ $sync -le 400 ]
	do
		echo $sync | sudo tee /sys/block/sda/queue/iosched/slice_sync 
		delay=0
		coe1=1
		while [ $delay -le 32 ]
		do
			sudo sync && echo 3 | sudo  tee /proc/sys/vm/drop_caches			
			i=$jobs
			
			while [ $i -ge 0 ]
			do 
				if $fio ;
				then
					echo " fio --ioengine=sync --filesize=10G --thinktime=$delay --threads=1 --rw=read --direct=1 --bs=512k --size=2048M --filename=./result/tmp_10G_$i --name=job_$i > ./result/fio_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ]_user$[ i ].log &"
					fio --ioengine=sync --filesize=10G --thinktime=$delay --threads=1 --rw=read --direct=1 --bs=512k --size=2048M --filename=./result/tmp_10G_$i --name=job_$i > ./result/fio_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ]_user$[ i ].log &
				else
					echo " iozone -w -J $delay -+T -i1 -I -r 512K  -s $[ 512*8 ]M -t 1  -F ./result/tmp_10G_$i > ./result/iozone_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ]_user$[ i ].log  &"
					iozone -w -J $delay -+T -i1 -I -r 512K  -s $[ 512*4 ]M -t 1  -F ./result/tmp_10G_$i > ./result/iozone_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ]_user$[ i ].log &
				fi

				pi=$!
				echo $pi | sudo tee /sys/fs/cgroup/blkio/user_$i/cgroup.procs				 				
				let pi_$[ i ]=pi
				let i=i-1
			done

			#iostat -x  2 sda >  ./result/iostat_sync$sync$idle$delay.log &
			#io=$!
			wait $pi_2
			wait $pi_1
			wait $pi_0
			#kill -9 $io
			#kill -15 $pi_1
			#kill -15 $pi_0
			sleep 3
			i=$jobs
			if $fio ; then
				while [ $i -ge 0 ]
				do
					var1=`awk -F"READ: io=" '{print $2}' ./result/fio_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ]_user$[ i ].log` 
					var=`awk -F"," '{print $1}' <<< $var1`
					declare "io$[ i ]"="$var"
					var1=`awk -F"aggrb=" '{print $2}' ./result/fio_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ]_user$[ i ].log`
					var=`awk -F"," '{print $1}' <<< $var1`
					declare "aggrb$[ i ]"="$var"
					var1=`awk -F"mint=" '{print $2}' ./result/fio_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ]_user$[ i ].log`
					var=`awk -F"," '{print $1}' <<< $var1`
					declare "mint$[ i ]"="$var"
					let i=i-1
				done
			else
								i=$jobs
				while [ $i -ge 0 ]
				do
					var=`awk '/Children see throughput for 1 readers/{print $(NF - 1), $NR}' ./result/iozone_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ]_user$[ i ].log`
					let thp$[ i ]=var
					let i=i-1
				done
			fi			

			cat /sys/kernel/debug/tracing/trace > ./result/trace_file_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ].txt
			time_spent_on_grp0=`awk '/cfq_dispatch_requests: weight: 250/{ SUM += $NF} END {print SUM}' ./result/trace_file_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ].txt`
			time_spent_on_grp1=`awk '/cfq_dispatch_requests: weight: 501/{ SUM += $NF} END {print SUM}' ./result/trace_file_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ].txt`
			time_spent_on_grp2=`awk '/cfq_dispatch_requests: weight: 750/{ SUM += $NF} END {print SUM}' ./result/trace_file_sync$[ sync ]_groupIdle$[ group_idle ]_idle$[ slice_idle ]_delay$[ delay ].txt`
			echo > /sys/kernel/debug/tracing/trace
		
			if $fio ; then
				echo "$slice_idle,$group_idle,$sync,$delay,$io0,$io1,$io2,$aggrb0,$aggrb1,$aggrb2,$mint0,$mint1,$mint2,$time_spent_on_grp0,$time_spent_on_grp1,$time_spent_on_grp2" >> $fio_output
			else
				echo "$slice_idle,$group_idle,$sync,$delay,$thp0,$thp1,$thp2,$time_spent_on_grp0,$time_spent_on_grp1,$time_spent_on_grp2" >> $fio_output
			fi
		let coe1=coe1*2
		let delay=coe1
		done

	let coe2=coe2*2
	let sync=coe2
	sleep 3
	done

let coe3=coe3*2
let slice_idle=coe3
sleep 3
done

python cat_cgroup_io.py

echo finish
