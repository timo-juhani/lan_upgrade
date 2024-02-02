# LAN Upgrade

## Introduction

How many times you work with networks that are outright insecure, vulnerable and unpatched? 
How often do you hear any of these:\
a) We don't have time to upgrade.\
b) We don't have an SDN or a programmable API to do this.\
c) We got hacked because of a known software vulnerability.\
d) We just had a major incident becasue the software base is so old.\
e) We didn't know networks need to be patched.

In reality most organizations have massive LAN networks. Therefore all points from a) to e) lead to 
a massive maintenance debt because they can't keep up with the patching requirements.

This project solves the problem by offering a shell program that automates typical software 
management tasks required to operate and secure modern Cisco switches. 

The design requirements for the project have been:
- The program runs over standard management interface - SSH that is used by if not all then 99% of 
  all organizations globally.
- It uses multithreading to run updates to multiple devices in parallel thus saving time and money.
- To reduce barriers of entry both technical and economical it uses open-source code available 
  through PyPI that anyone can download. 
- It runs on a standard Linux operating system to enable allow flexible deployment and portability.
- Any user with some networking and Linux shell experience should be able to adopt this tool
  quickly.

## Prerequisites

- Devices can be accessed with SSH using admin credentials.
- All devices must be in INSTALL mode, if not conversion from BUNDLE must be done.
- Python packages (pip install -r requirements.txt).
- Tested on Catalyst 9000 family with IOS-XE 17.x software.

## Working with Devices

There are two ways to work with the program: 1) inventory mode and 2) HOST mode. The first one uses
a .csv file called inventory.csv resides in the folder root by default. Both ways are fairly easy to
work with. The second one i.e. HOST mode accepts device parameters as shell arguments which is handy
if you are only dealing with a single device and/or don't care about managing a separate inventory 
files. 

### Credentials

SSH username:password combination is used. It can be either provided as a shell argument (raw or 
env variable for isntance) or as a user input while the program runs. 

```
./lan_upgrade.py -u admin -p pass123 -I activate
```

### Inventory Mode

In inventory mode you just punch in the device parameters in .csv format (please see the sample) and
let the code rely on them. Parameters required are the ones you probably expected:
- IP Address: Management IP address of the target device.
- OS: Operating system using Netmiko's value list. At the moment, only cisco_xe is supported by the 
- program.
- Hostname: The name of target device. This is simply used to make the logging output more readable.
  The program runs multithreading so as an operator it's great to see which device is in which step
  of the process without losing the picture as threads come and go.
- Target Image: The filename of the target binary, for example: cat9k_lite_iosxe.17.09.04a.SPA.bin
- Upgrade: yes/no to flag whether you are planning to upgrade the device. The program won't upgrade
  anything unless you explicitly give a permission. This is to keep the pistol in holster and not to
  cause unplanned outage due to moments of weak decision making. 

```
# Inventory mode is enabled with -I flag
./lan_upgrade.py -I activate
```

### HOST Mode

In HOST mode you just provide same parameters as in inventory mode but the method of doing that is 
via shell intead of using inventory.csv. The only difference is that in HOST mode there is no 
"upgrade" argument. The simple expectation is that when you choose to use HOST mode you have made 
a decision that the device is good to be upgraded if you run anything but info operations on it. 

```
# HOST mode requires setting the right flags. If it looks like a cluster mess, think of using env 
# variables.
# H = hostname
# O = operating system from Netmiko values
# S = software binary placed in folder root
# T = target's management IP address
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 info -s
```

## Gathering Info for Upgrades

### Check Control Connections

Not yet developed

### Check Devices in Bundle Mode

Devices that are in bundle mode should be migrated to install mode prior to trying to upgrade them.
Using the info operation together with bundle flag it's easy to scan through the inventory and 
figure out which devices needs to be coverted.  

```
# Inventory mode.
./lan_upgrade.py -I info -b

# HOST mode.
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 info -b
```

### Check Devices That Require Upgrade

Next, you'd like to know which devices need to be upgraded and which ones are already on the target
version. Using the info operation with scan software flag is the way to answer to that question. 

The information gathered on this step and a common undestanding of the network topology gives you 
enough knowledge to select devices that you'd like to upgrade by marking the upgrade parameter as 
"yes" in the inventory.

```
# Inventory mode.
./lan_upgrade.py -I info -s

# HOST mode.
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 info -s
```

## Cleaning Flash

Before trying to upgrade it's a good idea to check whether the devices are crammed with old unused 
versions that can be safely removed.

```
./lan_upgrade -I clean
```

## Upgrade

**Warning: Upgrade is a disruptive operation!**

Think, plan, pause and execute only if the maintenance has been scheduled. 
So don't go el pistolero. Don't be a cowboy. 

### Staged Install 

This is the most controlled approach that offers multiple points of return and none of them is 
ROMMON. In most case you would prefer to do upgrades using staging because it allows the upgrade
prep-work and even adding the image to the device done during normal business hours. During the 
maintenance window you'd then activate the image which triggers the device to reload. Even after 
if you see something odd and are not comfortable to commit the new version you have a change to 
abort the upgrade.

Add operation is simply for adding the target image to image repository on the device by expanding 
the .bin file to .pkg files. 

First thing it does is determining whether an upgrade is truly needed and wanted by checking the 
inventory file and comparing the target version to the running version on the target device.

Then it checks whether the image is already on the device and if not it uploads it there with SCP if 
there is enough disk space. Once the image is on the flash the program makes sure it is intact by 
verifying the MD5 hash. If the hash is alright it add the image using the install add command. 

Activate operation changes packages.conf to match with the new .pkg files of the target image. This 
operation comes with a reboot. Also, activate operation starts a rollback timer. This rollback 
feature implemented to IOS-XE does an automatic rollback to the previous version unless you commit 
the target version.

So if everything goes as planned after activate operation you'd check when the devices control 
channels are alive again and then commit the target version. If some something unfortunate happens
or you made a mistake there are two courses of action:
1. SSH into the device and abort (install abort)
2. Wait the rollback timer to hit zero and previous version gets rollback after the device reloads.

```
# Inventory mode
# Add image to the device's image repository for later activation.
./lan_upgrade.py -I add

# Activates the added image. 
# Warning: This cause the device to reboot
./lan_upgrade.py -I activate

# Commits the activated image.
./lan_upgrade.py -I commit

# HOST mode
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 add
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 activate
./lan_upgrade.py -H sdn-e30 -O cisco_xe -S cat9k_lite_iosxe.17.09.04a.SPA.bin -T 10.1.106.11 commit
```

### One-Shot Install (No Questions Asked)

OK, so I warned about the risks of trying to be a hero and getting after that badge of honor by 
cracking off rounds with your pistol. Plan your updates correctly and reload your devices in pre-
planned maintenance windows. 

But let's imagine for a moment that you feel an urge like you have never felt before. A superior
dark force compels you into a heinous action on a nice Friday afternoon when all your buddies are 
dreaming of heating sauna and drinking a few cold ones. Instead of all the warnings you decide to 
demote yourself to junior engineer status again, ruin everyone's calm afternoon and go for the final 
quick update. 

To cater for your appetite of destruction the program has full-install operation to go through all 
stages of the update using a one-shot CLI command that doesn't ask any user acknowledgements 
whatsoever. 

In all seriousness try to avoid this approach. And if you have to use it use it a controlled place 
where there is no real risk of hurting infra. A typical justification for using the one-shot is 
that the devices sit in the lab and you can reboot them as you please. Also full-install is used by 
the program when doing the coversion from bundle mode to install mode. 

```
./lan_upgrade.py -I full-install
```

## Troubleshooting

The program sends logs to stdout and application.log file. The default logging level is set to info.
But there could be times when you want to have the full debug capability enabled. 

```
# Switch on the debug mode 
./lan_upgrade.py -I info -s -d
```

## To Do: 
- Check control (SSH) connections
- What if there is nothing to activate