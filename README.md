# LAN Upgrade

## Intruction

## Prerequisites
- SSH access using admin credentials.
- All devices must be in INSTALL mode, if not conversion from BUNDLE must be done.
- Python packages (pip install -r requirements.txt)

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

```
./lan_upgrade.py -I info -b
```

### Check Devices That Require Upgrade

```
./lan_upgrade.py -I info -s
```

## Upgrade

### Staged Install 

```
./lan_upgrade.py -I add

./lan_upgrade.py -I activate

./lan_upgrade.py -I commit
```

### Full-Installation

```
./lan_upgrade.py -I full-install
```

## Troubleshooting

```
./lan_upgrade.py -I info -s -d
```

## To Do: 
- Check control (SSH) connections
- What if there is nothing to activate
- What if there is nothing to commit