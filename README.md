# LAN Upgrade

[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/timo-juhani/lan_upgrade)

## 1. Introduction

How many times you have worked with networks that are outright insecure, vulnerable and unpatched? 

How often do you hear any of these:\
a) We don't have time to upgrade.\
b) We don't have an SDN or a programmable API to do this.\
c) We got hacked because of a known software vulnerability.\
d) We just had a major incident because the software base is so old.\
e) We didn't know networks need to be patched.

In reality most organizations have massive LAN networks. Therefore all points from a) to e) lead to a huge maintenance debt because they can't keep up with the patching requirements.

This project solves the problem by implementing a Python based shell program that automates typical software management tasks required to operate and patch modern IOS-XE switches. 

The design requirements for the project are:
- The program runs over a standard management interface - SSH that is used by if not all then 99% of all organizations globally. Not all are willing to use RESTCONF or NETCONF just yet. That isn't an excuse for fixing the issue. 
- It uses multi-threading to run updates to multiple devices in parallel thus saving time and money.
- To reduce barriers of entry both technical and economical it uses open-source code available through PyPI that anyone can download such as Netmiko.
- It runs on a standard Linux operating system to allow flexible deployment and portability.
- Any user with some networking and Linux shell experience should be able to adopt this tool quickly. For the user it should feel like a no non-sense hacking tool. 
- It doesn't implement any fancy inventory database. Instead is relies on tools that we all know and have available. For inventory that should be either text editor or Excel. That said the inventory file should be trackable by Git.
- All organizations no matter which size or which region should have a basic capability to patch and operate secure networks. This should be fundamental as brushing teeth two times a day. When the foundation is rock solid everything else is easier.

## 2. Prerequisites

### 2.1 Notes

- Devices can be accessed with SSH using admin credentials.
- All devices must be in INSTALL mode, if not conversion from BUNDLE must be done. The program has an operation for that.
- Python version 3.10.12 or above.
- Python packages (pip install -r requirements.txt).
- Tested on Catalyst 9000 family with IOS-XE 17.x software. However, it's quite likely it works well on Catalyst 8000 router family as well.

### 2.2 Installation

```
# Get the code.
git clone https://github.com/timo-juhani/lan_upgrade.git

# Check that Python is installed.
python -V

# Install pip and venv.
sudo apt install python3-pip
pip install virtualenv

# Create a virtual environment.
python -m venv lan-upgrade

# Activate virtual environment.
source lan-upgrade/bin/activate

# Install required packages.
pip install -r requirements.txt
```

### 2.3 Installation with Docker

Sometimes it's a pain in the butt to deal with all Linux and Python dependencies. Especially so if you're using the program without Internet connectivity. In those case Docker image becomes handy. To bypass this via dolorosa build yourself a container that is easy to port between hosts regardless of Internet access.

```
# Build the image.
docker build -t lan-upgrade .

# Confirm.
docker images
docker run lan-upgrade -h
```

## 3. Working with Devices

There are two ways to work with the program: 1) inventory mode and 2) HOST mode. The first one uses a .csv file called inventory.csv which resides in the folder root by default. Both ways are fairly easy to work with. The second one i.e. HOST mode accepts device parameters as shell arguments which is handy if you are only dealing with a single device and/or don't care about managing a separate inventory file. 

### 3.1 Credentials

SSH username:password combination is used. It can be either provided as a shell argument (raw or env variable for instance) or as a user input while the program runs. 

```
./lan_upgrade.py -u admin -p pass123 -I activate
```

### 3.2 Inventory Mode

In inventory mode you just punch in the device parameters in .csv format (please see the sample) and let the code rely on them. Parameters required are the ones you probably expected:
- IP Address: Management IP address of the target device.
- OS: Operating system using Netmiko's value list. At the moment, only cisco_xe is supported by the program.
- Hostname: The name of the target device. This is simply makes the logging output more readable. The program runs multi-threading so as an operator it's great to see which device is in which step of the process without losing the picture as threads come and go.
- Target Image: The filename of the target binary, for example: cat9k_lite_iosxe.17.09.04a.SPA.bin
- Upgrade: yes/no to flag whether you are planning to upgrade the device. The program won't upgrade anything unless you explicitly give a permission. This is to keep the pistol in holster and not to cause unplanned outage due to unfortunate moments of weak decision making. 

```
# Inventory mode is enabled with -I flag
./lan_upgrade.py -I activate
```

It's a good idea to initially choose "no" as "upgrade" value for all devices in your inventory so that you can get familiar with the tool without sweating about the misfired upgrade. 

### 3.3 HOST Mode

In HOST mode you just provide same parameters as in inventory mode but the method of doing that is via shell intead of using inventory.csv. The only difference is that in HOST mode there is no "upgrade" argument. The simple expectation is that when you choose to use HOST mode you have made a decision that the device is good to be upgraded if you run anything but info operations on it. 

```
# HOST mode requires setting the right flags. If it looks like a cluster mess, think of using env 
# variables, a shell alias or a shell script - there are many ways to streamline the process to your
# taste.
# H = hostname
# O = operating system, at this point only cisco_xe supported
# S = software binary which is stored in folder root
# T = target device's management IP address
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 info -s
```

## 4. Gathering Info for Upgrades

### 4.1 Alive Test

Alive test keeps testing the devices with Ping until they respond again. This is handy during those long moments when devices are, for instance, rebooting after an upgrade. Furthermore, it makes sense to start the upgrade process by checking all your devices responding from their IP addresses.

```
./lan_upgrade.py -I info -a
```

### 4.2 Check Control Connections

Make sure the device(s) is reachable by pinging it and SSH'ing into it. Do this before running any other info or installation operations to make sure all is set. 

```
./lan_upgrade.py -I info -r
```

### 4.3 Check Devices in Bundle Mode

Devices that are in bundle mode should be migrated to install mode prior to trying to upgrade them. Using the info operation together with bundle flag it's easy to scan through the inventory and figure out which devices needs to be converted.  

```
# Inventory mode.
./lan_upgrade.py -I info -b

# HOST mode.
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 info -b
```

### 4.4 Check Devices That Require Upgrade

Next, you'd like to know which devices need to be upgraded and which ones are already on the target version. Using the info operation with scan software flag is the way to answer that question. 

The information gathered on this step and a common undestanding of the network topology gives you enough knowledge to select devices that you'd like to upgrade by marking the upgrade parameter as "yes" in the inventory.

```
# Inventory mode.
./lan_upgrade.py -I info -s

# HOST mode.
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 info -s
```

## 5. Cleaning Flash

Before trying to upgrade it's a good idea to check whether the devices are crammed with old unused versions that can be safely removed.

```
./lan_upgrade -I clean
```

## 6. Upgrade

**Warning: Upgrade is a disruptive operation!**

Think, plan, pause and execute only if the maintenance has been scheduled. 
Don't be a cowboy.

### 6.1 Staged Install 

This is the most controlled approach that offers multiple points of return and none of them is via ROMMON. In most cases you would prefer to do upgrades using staging because it allows the upgrade prep-work and even adding the image to the device done during normal business hours. During the maintenance window you'd then activate the image which triggers the device to reload. Even after if you see something odd and are not comfortable to commit the new version you have a change to abort the upgrade.

Add operation is simply for adding the target image to image repository on the device by expanding the .bin file to .pkg files. 

First thing it does is to find out whether an upgrade is truly needed and wanted by checking the inventory file and comparing the target version to the running version on the target device.

Then it checks whether the image is already on the device and if not it uploads it there with SCP if there is enough disk space. Once the image is on the flash the program makes sure it is intact by verifying the MD5 hash. If the hash is alright it adds the image using the install add command. 

Activate operation changes packages.conf to match with the new .pkg files of the target image. This operation comes with a reboot. Also, activate operation starts a rollback timer. This rollback feature implemented on IOS-XE does an automatic rollback to the previous version unless you commit the target version.

So if everything goes as planned after activate operation you'd check when the devices control channels are alive again and then commit the target version. If some something unfortunate happens
or you made a mistake there are two courses of action:
1. SSH into the device and abort (install abort)
2. Wait the rollback timer to hit zero and previous version installs as a rollback after the device reloads.

```
# Inventory mode
# Add image to the device's image repository for later activation.
./lan_upgrade.py -I add

# Activates the added image. 
# Warning: This cause the device to reboot
./lan_upgrade.py -I activate

# While the devices are rebooting use alive and reachability checks to see when they come up again.
./lan_upgrade.py -I info -a
./lan_upgrade.py -I info -r

# Commits the activated image.
./lan_upgrade.py -I commit

# Checks that software has been upgraded.
./lan_upgrade.py -I info -s

# HOST mode
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 add
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 activate
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 commit
```

### 6.2 One-Shot Install (No Questions Asked)

OK, so I warned about the risks of going el pitolero as you get after that badge of honor by focusing on shots fired instead of shots on target. Once more, plan your updates correctly and reload your devices in pre-planned maintenance windows. 

But let's imagine for a moment that you feel an urge like you have never felt before. A superior dark force compels you into a heinous action on a nice Friday afternoon when all your buddies are dreaming of heating sauna and drinking a few cold ones. Instead of all the warnings you decide to demote yourself to junior engineer status again, risk ruining everyone's calm afternoon and go for that final quick update. 

For your appetite of destruction the program has full-install operation to go through all stages of the update using a one-shot CLI command that doesn't ask any user acknowledgements whatsoever. 

In all seriousness try to avoid this approach. And if you have to use it use it a controlled place where there is no real risk of hurting uptime. A typical justification for using the one-shot is that the devices sit in the lab and you can reboot them as you please. Also full-install is used by the program when doing the coversion from bundle mode to install mode. 

```
./lan_upgrade.py -I full-install
```

## 7. Convert from BUNDLE to INSTALL

Most likely some of the devices in your LAN are running in BUNDLE mode. To convert from BUNDLE to INSTALL mode you can simply let the program do that for you. 

```
# Inventory mode
./lan_upgrade -I convert

# HOST mode
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 convert
```

## 8. Troubleshooting

The program sends logs to stdout and application.log file. The default logging level is set to info. But there could be times when you want to have the full debug capability enabled which allows you to see what is sent to the device and how it responds back in native IOS-XE messages.

```
# Switch on the debug mode 
./lan_upgrade.py -I info -s -d
```

## 9. Working with Docker

As mentioned before it is handy have Docker as an option in those environments with limited network access to public resources such as Linux package repositories or PyPI. Using the program with Docker is quite simple but it requires some considerations in regards to networking and storage. 

```
# The container is run like this. 
# -it flags runs the container with interactive shell which allows entering username and password.
# --network flag sets the container network which allows the container to join a VPN tunnel in case it's used.
# -v (--volume) flag sets the container volume to publish SW images and inventory to the container. 
# After that the execution is similar to the shell program. Dockerfile sets the entrypoint on the program. 
docker run -it --network=host -v ${PWD}:/lan-upgrade/ lan-upgrade -I info -s
```

## Afterword

This project will evolve as the organizations adopt new ways of managing their networks and IOS-XE code develops. The program will never cover all detailed aspects of software management. Instead, it lives by values of pareto principle, action before procrastination and power to the many instead of privileges to the few. As outdated software persist in Top 10 security issues year after year this project provides means to respond against one of the more structural problems affecting our industry today. 

Patch'em up.

Stay safe,

T-J
