#!/bin/bash
#
# This script downloads, installs and configure the Intel DPDK framework
# on a clean Ubuntu 16.04 installation running in a virtual machine.
#
# This script has been created based on the following scripts:
#  * https://gist.github.com/ConradIrwin/9077440
#  * http://dpdk.org/doc/quick-start


# Variables
# Get Command Line arguements if present
SHUKE_DIR=$1
if [ "x$1" != "x" ]; then
    SHUKE_DIR=$1
else
    SHUKE_DIR="/shuke"
fi
export RTE_TARGET="x86_64-native-linuxapp-gcc"
export RTE_SDK=`ls -d $SHUKE_DIR/3rd/dpdk-*`
HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`

echo "--------------------------------------------------------------"
echo "0:$0"
echo "1:$1"
echo "SHUKE_DIR:  $SHUKE_DIR"
echo "RTE_SDK:    $RTE_SDK"
echo "RTE_TARGET: $RTE_TARGET"
echo "HUGEPGSZ:   $HUGEPGSZ"
echo "--------------------------------------------------------------"

build_dpdk() {
    if [ ! -d "$RTE_SDK/$RTE_TARGET" ]; then
        echo "building dpdk for $RTE_TARGET"
        make -C $RTE_SDK install T=$RTE_TARGET
    else
        echo "dpdk is compiled, skip it"
    fi
}

#
# Creates hugepage filesystem.
#
create_mnt_huge()
{
	  echo "Creating /mnt/huge and mounting as hugetlbfs"
	  sudo mkdir -p /mnt/huge

	  grep -s '/mnt/huge' /proc/mounts > /dev/null
	  if [ $? -ne 0 ] ; then
		    sudo mount -t hugetlbfs nodev /mnt/huge
	  fi
}

#
# Removes hugepage filesystem.
#
remove_mnt_huge()
{
	  echo "Unmounting /mnt/huge and removing directory"
	  grep -s '/mnt/huge' /proc/mounts > /dev/null
	  if [ $? -eq 0 ] ; then
		    sudo umount /mnt/huge
	  fi

	  if [ -d /mnt/huge ] ; then
		    sudo rm -R /mnt/huge
	  fi
}

#
# Unloads igb_uio.ko.
#
remove_igb_uio_module()
{
	  echo "Unloading any existing DPDK UIO module"
	  /sbin/lsmod | grep -s igb_uio > /dev/null
	  if [ $? -eq 0 ] ; then
		    sudo /sbin/rmmod igb_uio
	  fi
}

#
# Loads new igb_uio.ko (and uio module if needed).
#
load_igb_uio_module()
{
	  if [ ! -f $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko ];then
		    echo "## ERROR: Target does not have the DPDK UIO Kernel Module."
		    echo "       To fix, please try to rebuild target."
		    return
	  fi

	  remove_igb_uio_module

	  /sbin/lsmod | grep -s uio > /dev/null
	  if [ $? -ne 0 ] ; then
		    modinfo uio > /dev/null
		    if [ $? -eq 0 ]; then
			      echo "Loading uio module"
			      sudo /sbin/modprobe uio
		    fi
	  fi

	  # UIO may be compiled into kernel, so it may not be an error if it can't
	  # be loaded.

	  echo "Loading DPDK UIO module"
	  sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko
	  if [ $? -ne 0 ] ; then
		    echo "## ERROR: Could not load kmod/igb_uio.ko."
		    exit 1
	  fi
}

#
# Unloads the rte_kni.ko module.
#
remove_kni_module()
{
	  echo "Unloading any existing DPDK KNI module"
	  /sbin/lsmod | grep -s rte_kni > /dev/null
	  if [ $? -eq 0 ] ; then
		    sudo /sbin/rmmod rte_kni
	  fi
}

#
# Loads the rte_kni.ko module.
#
load_kni_module()
{
    # Check that the KNI module is already built.
	  if [ ! -f $RTE_SDK/$RTE_TARGET/kmod/rte_kni.ko ];then
		    echo "## ERROR: Target does not have the DPDK KNI Module."
		    echo "       To fix, please try to rebuild target."
		    return
	  fi

    # Unload existing version if present.
	  remove_kni_module

    # Now try load the KNI module.
	  echo "Loading DPDK KNI module"
	  sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/rte_kni.ko
	  if [ $? -ne 0 ] ; then
		    echo "## ERROR: Could not load kmod/rte_kni.ko."
		    exit 1
	  fi
}
#
# Removes all reserved hugepages.
#
clear_huge_pages()
{
	echo > .echo_tmp
	for d in /sys/devices/system/node/node? ; do
		echo "echo 0 > $d/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" >> .echo_tmp
	done
	echo "Removing currently reserved hugepages"
	sudo sh .echo_tmp
	rm -f .echo_tmp

	remove_mnt_huge
}

#
# Creates hugepages.
#
set_non_numa_pages()
{
	clear_huge_pages

	Pages="$1"
	echo "Number of pages: $Pages"

	echo "echo $Pages > /sys/kernel/mm/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" > .echo_tmp

	echo "Reserving hugepages"
	sudo sh .echo_tmp
	rm -f .echo_tmp

	create_mnt_huge
}

#
# Creates hugepages on specific NUMA nodes.
#
set_numa_pages()
{
	clear_huge_pages

	echo ""
	echo "  Input the number of ${HUGEPGSZ} hugepages for each node"
	echo "  Example: to have 128MB of hugepages available per node in a 2MB huge page system,"
	echo "  enter '64' to reserve 64 * 2MB pages on each node"

	echo > .echo_tmp

	Pages="$1"
	for d in /sys/devices/system/node/node? ; do
		node=$(basename $d)
		echo -n "Number of pages for $node: $Pages"
		echo "echo $Pages > $d/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" >> .echo_tmp
	done
	echo "Reserving hugepages"
	sudo sh .echo_tmp
	rm -f .echo_tmp

	create_mnt_huge
}

# Install dependencies
sudo apt-get -qq update
sudo apt-get -y -qq install git clang doxygen hugepages build-essential libnuma-dev libpcap-dev inux-headers-`uname -r`

build_dpdk
# Install kernel modules
load_igb_uio_module
load_kni_module
set_non_numa_pages 512

# Bind secondary network adapter
# I need to set a second adapter in Vagrantfile
# Note that this NIC setup does not persist across reboots
nr_uio_if=`python $RTE_SDK/usertools/dpdk-devbind.py -s | grep "drv=igb_uio"|wc -l`
if [ $nr_uio_if -eq 0 ];
then
    for NET_IF_NAME in enp0s8 enp0s9
    do
        echo "bind $NET_IF_NAME to uio."
        sudo ifconfig ${NET_IF_NAME} down
        sudo ${RTE_SDK}/usertools/dpdk-devbind.py --bind=igb_uio ${NET_IF_NAME}
    done
else
    echo "devices have already been binded to uio, skip it."
fi

# Add env variables setting to .profile file so that they are set at each login
if grep -q "RTE_SDK" ${HOME}/.profile
then
    echo "RTE_SDK already in profile."
else
    echo "export RTE_SDK=${RTE_SDK}" >> ${HOME}/.profile
    echo "export RTE_TARGET=${RTE_TARGET}" >> ${HOME}/.profile
fi

sudo apt-get install -y autoconf libtool
# build shuke
make -C ${SHUKE_DIR}

install_mongo()
{
    sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 0C49F3730359A14518585931BC711F9BA15703C6
    echo "deb [ arch=amd64,arm64 ] http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.4.list
    sudo apt-get update
    sudo apt-get install -y mongodb-org --allow-unauthenticated
    sed -i 's/bindIp: /# bindIp: /g' /etc/mongod.conf
}

if ! which mongod >/dev/null
then
    echo "install mongodb."
    install_mongo
else
    echo "mongodb is already installed, skip it."
fi

sudo systemctl start mongod
