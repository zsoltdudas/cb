#!/bin/bash

########################################################################
#
# Linux on Hyper-V and Azure Test Code, ver. 1.0.0
# Copyright (c) Microsoft Corporation
#
# All rights reserved.
# Licensed under the Apache License, Version 2.0 (the ""License"");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
# ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR
# PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
#
# See the Apache Version 2.0 License for specific language governing
# permissions and limitations under the License.
#
########################################################################

########################################################################
#
# Script introduction TO DO
#
################################################################

declare os_VENDOR os_RELEASE os_UPDATE os_PACKAGE os_CODENAME

########################################################################
# Determine what OS is running
########################################################################
# GetOSVersion
function GetOSVersion {
    # Figure out which vendor we are
    if [[ -x "`which sw_vers 2>/dev/null`" ]]; then
        # OS/X
        os_VENDOR=`sw_vers -productName`
        os_RELEASE=`sw_vers -productVersion`
        os_UPDATE=${os_RELEASE##*.}
        os_RELEASE=${os_RELEASE%.*}
        os_PACKAGE=""
        if [[ "$os_RELEASE" =~ "10.7" ]]; then
            os_CODENAME="lion"
        elif [[ "$os_RELEASE" =~ "10.6" ]]; then
            os_CODENAME="snow leopard"
        elif [[ "$os_RELEASE" =~ "10.5" ]]; then
            os_CODENAME="leopard"
        elif [[ "$os_RELEASE" =~ "10.4" ]]; then
            os_CODENAME="tiger"
        elif [[ "$os_RELEASE" =~ "10.3" ]]; then
            os_CODENAME="panther"
        else
            os_CODENAME=""
        fi
    elif [[ -x $(which lsb_release 2>/dev/null) ]]; then
        os_VENDOR=$(lsb_release -i -s)
        os_RELEASE=$(lsb_release -r -s)
        os_UPDATE=""
        os_PACKAGE="rpm"
        if [[ "Debian,Ubuntu,LinuxMint" =~ $os_VENDOR ]]; then
            os_PACKAGE="deb"
        elif [[ "SUSE LINUX" =~ $os_VENDOR ]]; then
            lsb_release -d -s | grep -q openSUSE
            if [[ $? -eq 0 ]]; then
                os_VENDOR="openSUSE"
            fi
        elif [[ $os_VENDOR == "openSUSE project" ]]; then
            os_VENDOR="openSUSE"
        elif [[ $os_VENDOR =~ Red.*Hat ]]; then
            os_VENDOR="Red Hat"
        fi
        os_CODENAME=$(lsb_release -c -s)
    elif [[ -r /etc/redhat-release ]]; then
        # Red Hat Enterprise Linux Server release 5.5 (Tikanga)
        # Red Hat Enterprise Linux Server release 7.0 Beta (Maipo)
        # CentOS release 5.5 (Final)
        # CentOS Linux release 6.0 (Final)
        # Fedora release 16 (Verne)
        # XenServer release 6.2.0-70446c (xenenterprise)
        os_CODENAME=""
        for r in "Red Hat" CentOS Fedora XenServer; do
            os_VENDOR=$r
            if [[ -n "`grep \"$r\" /etc/redhat-release`" ]]; then
                ver=`sed -e 's/^.* \([0-9].*\) (\(.*\)).*$/\1\|\2/' /etc/redhat-release`
                os_CODENAME=${ver#*|}
                os_RELEASE=${ver%|*}
                os_UPDATE=${os_RELEASE##*.}
                os_RELEASE=${os_RELEASE%.*}
                break
            fi
            os_VENDOR=""
        done
        os_PACKAGE="rpm"
    elif [[ -r /etc/SuSE-release ]]; then
        for r in openSUSE "SUSE Linux"; do
            if [[ "$r" = "SUSE Linux" ]]; then
                os_VENDOR="SUSE LINUX"
            else
                os_VENDOR=$r
            fi

            if [[ -n "`grep \"$r\" /etc/SuSE-release`" ]]; then
                os_CODENAME=`grep "CODENAME = " /etc/SuSE-release | sed 's:.* = ::g'`
                os_RELEASE=`grep "VERSION = " /etc/SuSE-release | sed 's:.* = ::g'`
                os_UPDATE=`grep "PATCHLEVEL = " /etc/SuSE-release | sed 's:.* = ::g'`
                break
            fi
            os_VENDOR=""
        done
        os_PACKAGE="rpm"
    # If lsb_release is not installed, we should be able to detect Debian OS
    elif [[ -f /etc/debian_version ]] && [[ $(cat /proc/version) =~ "Debian" ]]; then
        os_VENDOR="Debian"
        os_PACKAGE="deb"
        os_CODENAME=$(awk '/VERSION=/' /etc/os-release | sed 's/VERSION=//' | sed -r 's/\"|\(|\)//g' | awk '{print $2}')
        os_RELEASE=$(awk '/VERSION_ID=/' /etc/os-release | sed 's/VERSION_ID=//' | sed 's/\"//g')
    fi
    export os_VENDOR os_RELEASE os_UPDATE os_PACKAGE os_CODENAME
}

########################################################################
# Determine if current distribution is a Fedora-based distribution
########################################################################
function is_fedora {
    if [[ -z "$os_VENDOR" ]]; then
        GetOSVersion
    fi

    [ "$os_VENDOR" = "Fedora" ] || [ "$os_VENDOR" = "Red Hat" ] || \
        [ "$os_VENDOR" = "CentOS" ] || [ "$os_VENDOR" = "OracleServer" ]
}

########################################################################
# Determine if current distribution is a SUSE-based distribution
########################################################################
function is_suse {
    if [[ -z "$os_VENDOR" ]]; then
        GetOSVersion
    fi

    [ "$os_VENDOR" = "openSUSE" ] || [ "$os_VENDOR" = "SUSE LINUX" ]
}

########################################################################
# Determine if current distribution is an Ubuntu-based distribution
########################################################################
function is_ubuntu {
    if [[ -z "$os_PACKAGE" ]]; then
        GetOSVersion
    fi
    [ "$os_PACKAGE" = "deb" ]
}

function copy_check (){


    if [ $? == 0 ] ; then
        echo "$1 successfully copied $2" >> summary.log
    else
        echo "ERROR: $1 failed copy $2" >> summary.log
fi

}

function rsa_keys(){
    cd ~
    if [ ! -d .ssh ] ; then
        mkdir .ssh
        echo ".ssh was created" >> summary.log
    else
        echo ".ssh already exists" >> summary.log
    fi

    file=$(echo $1 | grep -oP "[a-zA-Z-_0-9]*")

    cp $file ~/.ssh
    copy_check $file

    cp $file".pub" ~/.ssh
    copy_check $file".pub"

    cat $file".pub" > ~/.ssh/authorized_keys
    copy_check $file".pub" "in authorized_keys"
    chmod 600 ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/$file
    chmod 700 .ssh
}

function configure_ssh(){
    echo "Uncommenting #Port 22..."
    sed -i -e 's/#Port/Port/g' /etc/ssh/sshd_config
    if [ $? -eq 0 ]
    then
        echo "Uncomment Port succeeded." >> summary.log
    else
        echo "Error: Uncomment #Port failed." >> summary.log
    fi

    echo "Uncommenting #Protocol 2..."
    sed -i -e 's/#Protocol/Protocol/g' /etc/ssh/sshd_config
    if [ $? -eq 0 ]
    then
        echo "Uncomment Protocol succeeded." >> summary.log
    else
        echo "Error: Uncomment #Protocol failed." >> summary.log
    fi

    echo "Uncommenting #PermitRootLogin..."
    sed -i -e 's/#PermitRootLogin/PermitRootLogin/g' /etc/ssh/sshd_config
    if [ $? -eq 0 ]
    then
        echo "Uncomment #PermitRootLogin succeeded." >> summary.log
    else
        echo "Error: Uncomment #PermitRootLogin failed." >> summary.log
    fi

    echo "Uncommenting RSAAuthentication..."
    sed -i -e 's/#RSAAuthentication/RSAAuthentication/g' /etc/ssh/sshd_config
    if [ $? -eq 0 ]
    then
        echo "Uncomment #RSAAuthentication succeeded." >> summary.log
    else
        echo "Error: Uncomment #RSAAuthentication failed." >> summary.log
    fi

    echo "Uncommenting PubkeyAuthentication..."
    sed -i -e 's/#PubkeyAuthentication/PubkeyAuthentication/g' /etc/ssh/sshd_config
    if [ $? -eq 0 ]
    then
        echo "Uncomment #PubkeyAuthentication succeeded." >> summary.log
    else
        echo "Error: Uncomment #PubkeyAuthentication failed." >> summary.log
    fi

    echo "Uncommenting AuthorizedKeysFile..."
    sed -i -e 's/#AuthorizedKeysFile/AuthorizedKeysFile/g' /etc/ssh/sshd_config
    if [ $? -eq 0 ]
    then
        echo "Uncomment #AuthorizedKeysFile succeeded." >> summary.log
    else
        echo "Error: Uncomment #AuthorizedKeysFile failed." >> summary.log
    fi

    echo "Uncommenting PasswordAuthentication..."
    sed -i -e 's/#PasswordAuthentication/PasswordAuthentication/g' /etc/ssh/sshd_config
    if [ $? -eq 0 ]
    then
        echo "Uncomment #PasswordAuthentication succeeded." >> summary.log
    else
        echo "Error: Uncomment #PasswordAuthentication failed." >> summary.log
    fi
}

function install_lis(){
    umount /media
    echo "Mounting drive..." >> summary.log
    mount /dev/cdrom /media
    if [ $? -eq 0 ]; then
        echo "cdrom was successfully mounted" >> summary.log 
        cd /media
        rpm -qa | grep microsoft
        if [ $? -eq 0 ]; then
            echo "Lis drivers are on machine, we'll upgrade" >> summary.log
            ./upgrade.sh
        else
            echo "Lis drivers aren't on machine, we'll install them" >> summary.log
            ./install.sh
        fi
        cd ~
    else
        echo "Mount failed. Proceeding to load cdrom drivers"
        cd /lib/modules/`uname -r`/kernel/drivers/ata
        insmod ata_piix.ko
        verifyInsert=$?
        sleep 10
        if [ verifyInsert -eq 0 ]; then
            echo "ata_piix.ko successfully loaded" >> summary.log
            mount /dev/cdrom /media
            cd /media
            rpm -qa | grep microsoft
            if [ $? -eq 0 ]; then
                echo "Lis drivers are on machine, we'll upgrade" >> summary.log
                ./upgrade.sh
            else
                echo "Lis drivers aren't on machine, we'll install them" >> summary.log
                ./install.sh
            fi
        else
            echo "Error: ata_piix.ko insert failed" >> summary.log
            echo "Hyper-V Daemons will be installed by yum" >> summary.log
            yum install hyperv-daemons -y
            verify_install $? hyperv-daemons
        fi
        cd ~
    fi
}

function verify_install (){
    if [ $1 -eq 0 ]; then
        echo "$2 was successfully installed." >> summary.log
    else
        echo "Error: failed to install $2" >> summary.log
    fi
}

function install_stressapptest(){
	echo "Installing stressapptest..." >> summary.log
    
    svn checkout http://stressapptest.googlecode.com/svn/trunk/ stressapptest
    cd stressapptest
    ./configure
    make
    make install
    verify_install $? stressapptest
    cd ~   
}

function install_Stress_ng(){
    echo "Installing Stress-ng..." >> summary.log

    git clone https://github.com/ColinIanKing/stress-ng
    cd stress-ng
    make
    make install
    verify_install $? Stress
    cd ~
}

function configure_grub(){
	echo "Configuring GRUB..." >> summary.log
	if is_ubuntu ; then
		sed -i -e 's/DEFAULT=""/DEFAULT="console=tty0 console=ttyS1 crashkernel=256M@128M"/g' /etc/default/grub
		update-grub	
	elif is_fedora ; then
		if [ $os_RELEASE -eq 7 ] ; then
			sed -i -e 's/crashkernel=auto/crashkernel=256M@128M console=tty0 console=ttyS1/g' /etc/default/grub
			perl -pi -e "s/quiet//g" /etc/default/grub
            grub2-mkconfig -o /etc/grub2.cfg
		elif [ $os_RELEASE -eq 6 ] ; then
			sed -i -e 's/crashkernel=auto/crashkernel=256M@128M console=tty0 console=ttyS1/g' /boot/grub/grub.conf
		    perl -pi -e "s/quiet//g" /boot/grub/grub.conf
        fi	
	elif is_suse ; then
		if [ $os_RELEASE -eq 12 ] ; then
			sed -i -e 's/218M-:109M/256M@128M console=tty0 console=ttyS1/g' /etc/default/grub
			perl -pi -e "s/quiet//g" /etc/default/grub
            grub2-mkconfig -o /etc/grub2.cfg
		elif [ $os_RELEASE -eq 11 ]	; then
			sed -i -e 's/256M-:128M/256M@128M console=tty0 console=ttyS1/g' /boot/grub/menu.lst
            perl -pi -e "s/splash=silent//g" /boot/grub/menu.lst
		fi	
	fi
}

#######################################################################
#
# Main script body
#
#######################################################################

if is_fedora ; then
    echo "Starting the configuration..."

    rm -r /etc/udev/rules.d/70-persistant-net.rules
    if [ $? == 0 ] ; then
        echo "/etc/udev/rules.d/70-persistant-net.rules successfully removed" >> summary.log
    else
        echo "ERROR: /etc/udev/rules.d/70-persistant-net.rules cannot be removed" >> summary.log
    fi

    chkconfig iptables off
    if [ $? == 0 ] ; then
        echo "iptables turned off" >> summary.log
    else
        echo "ERROR: iptables cannot be turned off" >> summary.log
    fi

    if [ $os_RELEASE -eq 6 ]; then
        echo "Changing ONBOOT..."
        sed -i -e 's/ONBOOT=no/ONBOOT=yes/g' /etc/sysconfig/network-scripts/ifcfg-eth0 
        echo "Turning off selinux..." 
        echo 0 > /selinux/enforce
        echo "selinux=0" >> /boot/grub/grub.conf
        sed -i -e 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    fi

    echo "Registering the system..." >> summary.log

    if [ $# -ne 2 ]; then
    	echo "ERRROR: Incorrect number of arguments!" >> summary.log
    	echo "Usage: ./AIO.sh username password" >> summary.log
	fi
    username=$1
    password=$2

    echo "os_RELEASE: $os_RELEASE" >> summary.log
    echo "os_UPDATE: $os_UPDATE" >> summary.log
    if [[ $os_RELEASE == "6.0" ]] || \
       [[ $os_RELEASE -eq 6 ]] && \
       [[ $os_RELEASE -eq 0 ]]; then
        rhnreg_ks --username $username --password $password
    else 
        subscription-manager register --username $username --password $password
        subscription-manager attach --auto
    fi

    echo "Installing packages..." >> summary.log
    PACK_LIST=(openssh-server dos2unix at net-tools gpm bridge-utils btrfs-progs xfsprogs ntp crash bc
        libaio-devel libattr-devel keyutils-libs-devel nano kexec-tools device-mapper-multipath expect sysstat)
    for item in ${PACK_LIST[*]}
    do
        echo "Starting to install $item... "
        yum install $item -y
        verify_install $? $item
    done
 
    install_stressapptest

    echo "Installing lis and mounting..."
    install_lis

elif is_ubuntu ; then
    echo "Starting the configuration..."
    
    PACK_LIST=(kdump-tools openssh-server tofrodos dosfstools dos2unix ntp gcc open-iscsi iperf gpm vlan iozone3 at multipath-tools expect
        make libattr1-dev stressapptest git bridge-utils btrfs-tools libkeyutils-dev xfsprogs linux-cloud-tools-common linux-tools-`uname -r` linux-cloud-tools-`uname -r` sysstat)
    for item in ${PACK_LIST[*]}
    do
        echo "Starting to install $item... "
        apt-get install $item -y
        verify_install $? $item
    done   

elif is_suse ; then
	# SLES ISO must be mounted for BETA releases
    chkconfig atd on
    service atd start
    echo "Registering the system..." >> summary.log
    if [ $# -ne 2 ]; then
        echo "ERRROR: Incorrect number of arguments!" >> summary.log
        echo "Usage: ./AIO.sh username password" >> summary.log
    fi
    username=$1
    password=$2

    if [ $os_RELEASE -eq 12 ]; then
        echo "Registering SLES 11" >> summary.log
        SUSEConnect -r $password -e $username
        #Adding repo for SVN
        zypper addrepo http://download.opensuse.org/repositories/devel:tools:scm:svn/SLE_12/devel:tools:scm:svn.repo
        zypper --no-gpg-checks refresh

    elif [ $os_RELEASE -eq 11 ]; then
    	echo "Registering SLES 11" >> summary.log
        suse_register -a regcode-sles=$password -a email=$username -L /root/.suse_register.log
        #Adding repo for SVN
        zypper addrepo http://download.opensuse.org/repositories/devel:tools:scm:svn/SLE_11_SP4/devel:tools:scm:svn.repo
        zypper --no-gpg-checks refresh
       
    else
    	echo "ERROR: Unsupported version of SLES!" >> summary.log
    fi

    echo "Installing dependencies for SLES 12" >> summary.log
    #Installing dependencies for stress-ng to work
    #First one needed is keyutils
    wget https://build.opensuse.org/source/security/keyutils/keyutils-1.5.9.tar.bz2
    tar -xjvf keyutils-1.5.9.tar.bz2
    cd keyutils-1.5.9/
    make
    make install
    cd ~
    
    #Second one is xattr. Just moving the file where stress-ng is searching for it
    mkdir /usr/include/attr/
    cp /usr/include/sys/xattr.h /usr/include/attr/xattr.h


    PACK_LIST=(at dos2unix dosfstools git-core subversion ntp gcc gcc-c++ expect sysstat)
    for item in ${PACK_LIST[*]}
    do
        echo "Starting to install $item... " >> summary.log
        zypper --non-interactive in $item 
        verify_install $? $item
    done

    install_stressapptest
fi

install_Stress_ng
configure_grub
rsa_keys rhel5_id_rsa
configure_ssh
