#!/bin/bash

install() {
    cd /opt/
    sudo git clone https://github.com/binexisHATT/3agL3.git
    sudo apt install python3-pip
    sudo pip3 install -r /opt/3agL3/requirements.txt

   	ln -s /opt/3agL3/main.py /usr/local/bin/3agL3
   	if [[ $? == 0 ]]
   	then
   		echo "Succesfully created symbolic link to -> /opt/3agL3/main.py"
   	else
   		echo "Couldn't created symbolic link to -> /opt/3agL3/main.py"
}

install