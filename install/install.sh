#!/bin/bash

THIS_FILE=$0
if [[ "$EUID" != "0" ]]
then
	echo "[!] Please run \`${THIS_FILE:2}\` as root (sudo)"
	exit 1
fi

function install_3agl3 {
	echo "[+] Installing python3 pip"
	apt install python3-pip
	cd /opt

	git clone https://github.com/binexisHATT/3agL3.git &> /dev/null
	GIT_INSTALLED=$?
	if [[ "$GIT_INSTALLED" -eq "0" ]]
	then
		echo "[+] Cloning 3agl3 repository"
	else
		echo "[-] Git is not installed. Please install Git and run 'install.sh' again"
		exit 1
	fi
	
	chmod +x /opt/3agL3/main.py
	pip3 install -r /opt/3agL3/requirements.txt
	ln -s /opt/3agL3/main.py /bin/3agL3

	if [[ "$?" -eq "0" ]]
   	then
   		echo "-----------------------------------------------------------------------"
   		echo "[+] Succesfully created symbolic link to -> /opt/3agL3/main.py as 3agL3"
   	else
   		echo "[-] Couldn't created symbolic link to -> /opt/3agL3/main.py"
   	fi
}

install_3agl3

echo "[+] Type 'sudo 3agL3 -h' for 3agL3 help menu"