#!/bin/bash

error (){
echo $0: usage: "
		-g|cgroups (number of control groups)
		-w|weight  (weight of the control groups)
		-r|run (run cgroups)"
exit 1	
}

if [ ! $# -gt 1 ]; then
	error    
fi

DIRECTORY=/sys/fs/cgroup/blkio/user_
create_groups () {
jobs=("${@}")
job=0
for weight in ${jobs[@]}
do
	if [ ! -d "$DIRECTORY$job" ]; then
	    mkdir $DIRECTORY$job
	    if [ $? -ne 0 ]; then
	    	return -1
	    fi
	    echo "created blk cgroup $DIRECTORY$job"	  	
	fi
	
	echo "8:0 $weight" > $DIRECTORY$job/blkio.weight_device
	if [ $? -ne 0 ]
	then
	    return -1
	fi

	echo "$DIRECTORY$job: block cgroup"
	echo "                          |"
	echo "                           --------weight_device: $weight"
	echo "                          |"
	job=$(($job+1))
done
return 0
}

#main
declare -a jobs
JOBS=0
run=false
re='^[0-9]+$'
while [ $# -ge 1 ]
do
	case $1 in
	    -g|--cgroup_jobs)
	    JOBS="$2"
	    job=0;
	    shift   
	    ;;
	    -w|--weights)
	    if [ $JOBS -le 0 ]; then
		echo $0: "no groups mentioned"
	    fi	    
	    while [ $job -lt $JOBS ]
	    do
		if ! [[ $2 =~ $re ]] ; then
		   echo $0: "weight of the groups not mentioned"
		   exit 1
		fi
		jobs=("${jobs[@]} $2")
		job=$(($job + 1))
		shift
	    done
	    ;;
	    -r|--run_jobs)
	    run=true
	    ;;
	    *)
	    error
	    ;;
	esac
	shift
done

if [ $JOBS -eq 0 ] || [[ $job -ne $JOBS ]]  ; then
	error
fi

sudo mount -t tmpfs cgroup_root /sys/fs/cgroup
sudo mkdir /sys/fs/cgroup/blkio
sudo mount -t cgroup blkio -o blkio /sys/fs/cgroup/blkio/

create_groups "${jobs[@]}"
if [ $? -ne 0 ]; then
	error
fi

if $run ; then
	./run_iozone.sh -g $JOBS
fi

#start_work() {
#start=0
#end=$(($2-1))
#for job in $(eval echo "{$start..$end}")
#do
#	echo "cgexec -g blkio:"group"$job $1"
#	cgexec -g blkio:"group"$job $1 &
#	if [ $? -ne 0 ]; then
#	    echo $0: usage: "error creating jobs"
#	    return -1
#	fi
#	job=$(($job+1))
#done
#}

#start_work "$work" "$JOBS"
#if [ $? -ne 0 ]; then
#	echo $0: usage: "error creating jobs"
#	exit 1
#fi

exit 0;
