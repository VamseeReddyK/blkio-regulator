#!/bin/bash

sudo mount -t tmpfs cgroup_root /sys/fs/cgroup
sudo mkdir /sys/fs/cgroup/cpuset
sudo mount -t cgroup cpuset -o cpuset /sys/fs/cgroup/cpuset/
sudo mkdir /sys/fs/cgroup/blkio
sudo mount -t cgroup blkio -o blkio /sys/fs/cgroup/blkio/
sudo mkdir /sys/fs/cgroup/blkio/user_1
sudo mkdir /sys/fs/cgroup/blkio/user_2
sudo mkdir /sys/fs/cgroup/blkio/user_3
