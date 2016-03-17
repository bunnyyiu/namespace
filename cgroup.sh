#!/bin/bash

# This script use cgroup to set the memory and CPU limit.

containerName=$1
pid=$2
group=/container/$containerName

memory=""
cpu_shares=""
cpu_period=""
cpu_quota=""

while [ "$3" != "" ]; do
  case $3 in
    -m | --memory )
      shift
      memory=$3
      ;;
    -c | --cpu_shares )
      shift
      cpu_shares=$3
      ;;
    -p | --cpu_period )
      shift
      cpu_period=$3
      ;;
    -q | --cpu_quota )
      shift
      cpu_quota=$3
      ;;
  esac
  shift
done

# This setup the hierarchy for cgroup
for sub in $(lssubsys -a);do
  cgcreate -g $sub:$group
done

rootCpusetMens=`cgget -nv -r cpuset.mems /`
rootCpusetCpus=`cgget -nv -r cpuset.cpus /`

# For unknown reasons, these values are empty by default
cgset -r cpuset.mems=$rootCpusetMens container
cgset -r cpuset.cpus=$rootCpusetCpus container

cgset -r cpuset.mems=$rootCpusetMens $group
cgset -r cpuset.cpus=$rootCpusetCpus $group

if [ "$memory" != "" ]; then
  cgset -r memory.limit_in_bytes=$memory $group
fi

if [ "$cpu_shares" != "" ]; then
  cgset -r cpu.shares=$cpu_shares $group
fi

if [ "$cpu_period" != "" ]; then
  cgset -r cpu.cfs_period_us=$cpu_period $group
fi

if [ "$cpu_quota" != "" ]; then
  cgset -r cpu.cfs_quota_us=$cpu_quota $group
fi

# Add pid to the cgroup
cgclassify -g *:$group $pid
