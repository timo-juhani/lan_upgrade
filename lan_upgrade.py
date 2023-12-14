#!/usr/bin/env python
"""
LAN UPGRADE FOR IOS-XE SWITCHES
Timo-Juhani Karjalainen, tkarjala@cisco.com, Cisco CX
2023
"""

# IMPORTS

import os
import sys
import subprocess
import re
import threading
import getpass
import logging
import argparse
import netmiko
import pyfiglet
import pandas
import termcolor

# FUNCTION DEFINITIONS

def exception_handler(func):
    """
    Decorator to catch exceptions. 
    Returns the function or exits the program if an exception occurs.
    """
    def inner_function(device, username, password, *args, **kwargs):
        try:
            return func(device, username, password, *args, **kwargs)
        except netmiko.exceptions.NetmikoAuthenticationException as err:
            msg = f"({device['name']}) Error: Authentication to device failed: {err}"
            print(termcolor.colored(msg, "red"))
            return sys.exit(1)
        except netmiko.exceptions.NetmikoTimeoutException as err:
            msg = f"({device['name']}) Error: Device connection time out: {err}"
            print(termcolor.colored(msg, "red"))
            return sys.exit(1)
        except Exception as err:
            msg = f"({device['name']}) Error: {err}"
            print(termcolor.colored(msg, "red"))
            return sys.exit(1)
    return inner_function

def run_multithreaded(function, inventory, username, password):
    """
    Use multithreading for updating multiple devicese simultaneously instead
    of in sequence. Ideally this should save a significant amount of time when
    the network is large.
    """
    config_threads_list = []
    for hostname, device in inventory.items():
        print(f"({device['name']}) Creating a thread.")
        # The name of the thread is the name of the device being configured.
        config_threads_list.append(threading.Thread(target=function, name=hostname, args=(device,
                                                    username, password)))
    # Start threads. The use of .join() allows the main execution of all threads
    # finish before the main program ends.
    for thread in config_threads_list:
        thread.start()
    for thread in config_threads_list:
        thread.join()

@exception_handler
def open_connection(device, username, password):
    """
    Open as connection to the target device. 
    Returns a ConnectHandler object or an error. 
    """
    print(f"({device['name']}) Connecting to device.")
    net_connect = netmiko.ConnectHandler(device_type=device['type'], ip=device['ipaddr'],
                                        username=username, password=password)
    return net_connect

def print_inventory(inventory_file_path):
    """
    Prints the contents of the inventory.csv to the console.
    """
    print("\nInventory:\n")
    # Print the content of the inventory file.
    with open(inventory_file_path, newline='', encoding='utf-8') as csvfile:
        print(pandas.read_csv(csvfile))
        print("\n")

def read_inventory(inventory_file_path):
    """
    Reads the inventory.csv file.
    Returns a dictionary that contains information about each device defined by
    the user.
    """
    devices = {}
    # Open the inventory file for reading the devices info.
    with open(inventory_file_path, encoding='utf-8') as inventory:
        # The first line in CSV is a header which needs to be skipped.
        next(inventory)
        # After the header has been skipped devices can be loaded to the dict.
        for item in inventory:
            # Create a list of each device using comma delimeter (.csv)
            device_info = item.strip().split(',')
            device = {"ipaddr": device_info[0], "type": device_info[1], "name": device_info[2],
                      "target-version": device_info[3], "upgrade": device_info[4]}
            # Each dictionary object is uniquely identified using hostname.
            devices[device['name']] = device
    return devices

def verify_space_iosxe(device, net_connect,file):
    """
    Check that there is enough space on the bootflash for the new image.
    Returns two booleans that provide information whether there is enough disk 
    space and whether the target .bin exists on the device already.
    """
    print(f"({device['name']}) Checking disk space.")
    # Check what files are on the disk.
    result = net_connect.send_command("show flash:")
    # Using Regex parse how many bytes are free.
    reg = re.compile(r'(\d+)\sbytes\savailable')
    space = int(reg.findall(result)[0])
    # Using Regex parse if the software binary is already on the disk.
    reg = re.compile(fr"{file}")
    exist = reg.findall(result)
    f_size = os.path.getsize(file)
    if space >= f_size:
        enough_space = 'True'
    if space < f_size:
        enough_space = 'False'
    if exist:
        image_exists = 'True'
    else:
        image_exists = 'False'
    return enough_space,image_exists

def check_md5(file):
    """
    Calculate the MD5 checksum of the software image in storage.
    Returns the expected hash value of the locally stored target image.
    """
    # Shell command on Linux systems to calculate a hash.
    # Get the output and parse the hash value from it.
    command = 'md5sum ' + file
    output = subprocess.getoutput(command)
    md5 = output.split(' ')[0]
    print(f"(Global) Info: Expected MD5 hash is {md5}")
    return md5

def verify_md5(net_connect, device, md5):
    """
    Verify that the MD5 checksum is as expected.
    Return True if image verification passes and False otherwise.
    """
    print(f"({device['name']}) Verifying MD5 hash of the image.")
    # Time out increased since verify command could take time.
    # Note that 5 min is an overkill but safe.
    result = net_connect.send_command(f"verify /md5 flash:{device['target-version']} {md5}",
                                      read_timeout=300)
    # User Regex to find the Verified string from the CLI output.
    reg = re.compile(r'Verified')
    md5_verified = reg.findall(result)
    if md5_verified:
        msg = f"({device['name']}) Success: Image verification passed."
        print(termcolor.colored(msg, "green"))
        result = True
    else:
        print(f"({device['name']}) Error: Image verification failed.")
        result = False
    return md5_verified

def enable_scp(net_connect, device):
    """
    Enable SCP server on the target device.
    """
    #try:
    # SCP is enabled if not already enabled. Line exec-timeout is increased
    # to ensure the image has time to upload properly.
    print(f"({device['name']}) Enabling SCP server now.")
    commands = [
        "ip scp server enable", 
        "line vty 0 4", 
        "exec-timeout 60"
        ]
    net_connect.send_config_set(commands)
    msg = f"({device['name']}) Success: Enabled SCP server and exec-timeout increased."
    print(termcolor.colored(msg, "green"))

def copy_upgrade_image(net_connect, device):
    """
    Upload the image to the target device using SCP file transfer.
    """
    # Create a new SSH connection and transfer the file over SCP.
    # If the file already exist don't overwrite it.
    print(f"({device['name']}) Uploading the image now.")
    netmiko.file_transfer(net_connect, source_file=device["target-version"],
                          dest_file=device["target-version"], file_system="flash:", direction="put",
                          overwrite_file=False)
    msg = f"({device['name']}) Success: Upload completed."
    print(termcolor.colored(msg, "green"))

def install_add(net_connect, device):
    """ 
    Using install command add the upgrade image to the device's image 
    repository.
    """
    print(f"({device['name']}) Starting to install the new image.")
    print(f"({device['name']}) Saving configuration.")
    net_connect.send_command('write memory', read_timeout=60)
    print(f"({device['name']}) Adding the new image.")
    net_connect.send_command(f"install add file flash:{device['target-version']}", read_timeout=660)
    msg = f"({device['name']}) Success: The new image was added."
    print(termcolor.colored(msg, "green"))

def verify_and_run_install_add(net_connect, device):
    """
    Add the image to the device's image repository only if the MD5 checksum is 
    ok.
    """
    md5 = check_md5(device["target-version"])
    md5_verified = verify_md5(net_connect, device, md5)
    if md5_verified:
        install_add(net_connect,device)
    else:
        print(f"({device['name']}) Error: Aborting the upgrade.")

@exception_handler
def add_image_process(device, username, password):
    """
    Adds the image to the device's image repository after running space and 
    image existence checks, copying the image to the device and verifying that 
    the MD5 checksum matches with the expected.
    """
    # Check that the device has been defined as IOS-XE device in the inventory.
    # If it's not exit the function gracefully.
    if device['type'] == 'cisco_xe' and device["upgrade"] == "yes":
        net_connect = open_connection(device, username, password)     
        print (f"({device['name']}) Preparing to upload image: {device['target-version']}")
        enough_space, image_exists = verify_space_iosxe(device, net_connect,
                                                        device["target-version"])
        if enough_space == 'True' and image_exists == 'False':
            msg = f"({device['name']}) Success: Device has space and image doesn't exist."
            print(termcolor.colored(msg, "green"))
            enable_scp(net_connect, device)
            copy_upgrade_image(net_connect, device)
            verify_and_run_install_add(net_connect, device)
        elif enough_space == 'False':
            print(f"({device['name']}) Error: Not enough space. Try 'install remove inactive' on ",
                  "the device.")
        elif image_exists == 'True':
            print(f"({device['name']}) Target image exists.")
            verify_and_run_install_add(net_connect, device)
        net_connect.disconnect()
    elif device["upgrade"] == "no":
        msg = f"({device['name']}) Error: Device not flagged to be upgraded (see inventory.csv)."
        print(termcolor.colored(msg, "red"))
        sys.exit(1)
    else:
        msg = f"({device['name']}) Error: Device type {device['type']} not supported."
        print(termcolor.colored(msg, "red"))
        sys.exit(1)

@exception_handler
def activate_image(device, username, password):
    """ 
    Activates the new image using install activate command. The reload is auto-
    approved after activation has compeleted.
    """
    if device['type'] == 'cisco_xe' and device["upgrade"] == "yes":
        net_connect = open_connection(device, username, password)
        print(f"({device['name']}) Starting to activate the new image.")
        print(f"({device['name']}) Activating the new image.")
        net_connect.send_command('install activate', read_timeout=660,
                                expect_string=r"This operation may require a reload of the system. Do you want to proceed"
                                )
        net_connect.send_command('y')
        msg = f"({device['name']}) Success: New image activated and reload approved. Reloading!"
        print(termcolor.colored(msg, "green"))
        net_connect.disconnect()
    elif device["upgrade"] == "no":
        msg = f"({device['name']}) Error: Device not flagged to be upgraded (see inventory.csv)."
        print(termcolor.colored(msg, "red"))
        sys.exit(1)
    else:
        msg = f"({device['name']}) Error: Device type {device['type']} not supported."
        print(termcolor.colored(msg, "red"))
        sys.exit(1)

@exception_handler
def commit_image(device, username, password):
    """ 
    Commits the new image using install commit command.
    """
    if device['type'] == 'cisco_xe' and device["upgrade"] == "yes":
        net_connect = open_connection(device, username, password)
        print(f"({device['name']}) Starting to commit the new image.")
        print(f"({device['name']}) Commit the new image.")
        net_connect.send_command('install commit', read_timeout=660)
        msg = f"({device['name']}) Success: Commit complete. Device upgraded."
        print(termcolor.colored(msg, "green"))
        net_connect.disconnect()
    elif device["upgrade"] == "no":
        msg = f"({device['name']}) Error: Device not flagged to be upgraded (see inventory.csv)."
        print(termcolor.colored(msg, "red"))
        sys.exit(1)
    else:
        msg = f"({device['name']}) Error: Device type {device['type']} not supported."
        print(termcolor.colored(msg, "red"))
        sys.exit(1)

@exception_handler
def clean_disk(device, username, password):
    """ 
    Clean the device flash from inactive and unused images in order to free up
    space for the upgrade.
    """
    if device['type'] == 'cisco_xe':
        net_connect = open_connection(device, username, password)   
        print(f"({device['name']}) Starting to clean the device from inactive images.")
        net_connect.send_command('install remove inactive', read_timeout=660,
                                expect_string=r"Do you want to remove the above files")
        net_connect.send_command('y')
        msg = f"({device['name']}) Success: Clean complete."
        print(termcolor.colored(msg, "green"))
        net_connect.disconnect()
    else:
        print (f"({device['name']}) Error: Device type {device['type']} not supported.")
        sys.exit(1)

@exception_handler
def full_install_no_prompts(device, username, password):
    """ 
    Adds, activate and commits the image using install commands without raising prompts for the 
    user. It enables a one step install for users that doesn't require a phased approach with add, 
    activate and commit commands. 
    """
    if device["type"] == "cisco_xe" and device["upgrade"] == "yes":
        net_connect = open_connection(device, username, password)
        print(f"({device['name']}) Saving configuration.")
        net_connect.send_command('write memory', read_timeout=60)
        print(f"({device['name']}) Starting full install without prompts.")
        net_connect.send_command(f"install add file flash:{device['target-version']} activate commit prompt-level none",
                                read_timeout=900)
        print(f"({device['name']}) Success: Full install complete. Device rebooting.")
        net_connect.disconnect()
    elif device["upgrade"] == "no":
        msg = f"({device['name']}) Error: Device not flagged to be upgraded (see inventory.csv)."
        print(termcolor.colored(msg, "red"))
        sys.exit(1)
    else:
        msg = f"({device['name']}) Error: Device type {device['type']} not supported."
        print(termcolor.colored(msg, "red"))
        sys.exit(1)

@exception_handler
def find_bundle_mode(device, username, password):
    """
    Scans the device configuration to find whether the device is in bundle mode.
    Returns true if in bundle mode or false if not. 
    """
    if device['type'] == 'cisco_xe':
        net_connect = open_connection(device, username, password)
        print(f"({device['name']}) Getting show commands.")
        print(f"({device['name']}) Get 'show version'.")
        output = net_connect.send_command('show version', read_timeout=60)
        net_connect.disconnect()
        if "BUNDLE" in output:
            msg = "Warning: Device in BUNDLE mode. Convert to INSTALL before upgrade."
            print(termcolor.colored(f"({device['name']}) {msg}", "yellow"))
        elif "INSTALL" in output:
            msg = "Success: Device in INSTALL mode."
            print(termcolor.colored(f"({device['name']}) {msg}", "green"))
        else:
            msg = "Error: Can't determine whether in INSTALL or BUNDLE mode. Manual check required."
            print(termcolor.colored(f"({device['name']}) {msg}", "red"))
    else:
        print (f"({device['name']}) Error: Device type {device['type']} not supported.")
        sys.exit(1)

@exception_handler
def find_ios_version(device, username, password):
    """
    Scans the device(s) for IOS version.
    Prints the version.
    """
    if device['type'] == 'cisco_xe':
        net_connect = open_connection(device, username, password)
        print(f"({device['name']}) Getting show commands.")
        print(f"({device['name']}) Get 'show version'.")
        output = net_connect.send_command('show version', read_timeout=60)
        net_connect.disconnect()
        for line in output.split("\n"):
            if 'Cisco IOS XE Software' in line:
                software_version = line.split(",")[1]
                msg = f"Success: {software_version}"
                print(termcolor.colored(f"({device['name']}) {msg}", "green"))
    else:
        print (f"({device['name']}) Error: Device type {device['type']} not supported.")
        sys.exit(1)

# MAIN FUNCTION

def main():
    """
    Executes the main program. 
    """
    # Print the welcome banner.
    banner = pyfiglet.figlet_format("LAN Upgrade", font="slant")
    print("\n")
    print(termcolor.colored(banner, "cyan"))

    # Create the command parser.
    parser = argparse.ArgumentParser(description="Shell application for running upgrades.")
    parser.add_argument("operation", type=str, help= """Choose the operation to be performed: info,
                        add, activate, commit, clean, full-install""")
    parser.add_argument("-u", "--username", type=str, help="Username of the admin user.")
    parser.add_argument("-p", "--password", type=str, help="Password of the admin user.")
    parser.add_argument("-I", "--inventorymode", type=bool, help="INVENTORY mode: enable.",
                        action=argparse.BooleanOptionalAction)
    parser.add_argument("-i", "--inventory", type=bool, help="Display inventory.",
                        action=argparse.BooleanOptionalAction)
    parser.add_argument("-b", "--bundle", type=bool, help="Display devices in bundle mode.",
                        action=argparse.BooleanOptionalAction)
    parser.add_argument("-s", "--scansoftware", type=bool, help="Display software versions.",
                        action=argparse.BooleanOptionalAction)
    parser.add_argument("-H", "--hostname", type=str, help="HOST mode: hostname.")
    parser.add_argument("-O", "--os", type=str, help="HOST mode: OS type (cisco_xe).")
    parser.add_argument("-S", "--software", type=str, help="HOST mode: Software image (*.bin).")
    parser.add_argument("-T", "--target", type=str, help="HOST mode: IP address.")
    args = parser.parse_args()

    # Save variables from arguments provided by the user.
    operation = args.operation
    username = args.username
    password = args.password
    inventory_mode = args.inventorymode
    inventory_display = args.inventory
    scan_for_bundle = args.bundle
    scan_for_versions = args.scansoftware
    hostname = args.hostname
    operating_system = args.os
    software_version = args.software
    target = args.target
    device = {hostname: {"ipaddr": target, "type": operating_system, "name": hostname,
              "target-version": software_version, "upgrade": "yes"}}

    # Start logging.
    # If there is an old log file delete it first.
    console_file = "console.log"
    if os.path.isfile(console_file):
        os.remove(console_file)
    logging.basicConfig(filename=console_file, level=logging.DEBUG)

    # Ask for administrative credentials if those haven't been provided as arguments.
    if username is None:
        username = input("Management username: ")
    if password is None:
        password = getpass.getpass(prompt ="Management password: ")

    # Inventory is hardcoded as inventory.csv for simplicity.
    inventory_file_path = "inventory.csv"

    # Run the program in either HOST or INVENTORY mode. 
    # HOST gets a single device parameters as arguments whereas INVENTORY is just read from .csv.
    if (hostname is not None and operating_system is not None and software_version is not None
        and target is not None):
        print(termcolor.colored("Success: Entering HOST mode.", "green"))
        inventory = device
    elif (hostname is None or operating_system is None or software_version is None
            or target is None) and inventory_mode is False:
        msg = "Error: HOST mode requires hostname, os, software and target flag - check your flags."
        print(termcolor.colored(msg, "red"))
        sys.exit(1)
    else:
        inventory = read_inventory(inventory_file_path)

    # Depending on the selected positional argument run a different action
    # using multithreading against the list of devices defined in inventory.csv.
    if operation == "add":
        run_multithreaded(add_image_process, inventory, username, password)
    elif operation == "activate":
        run_multithreaded(activate_image, inventory, username, password)
    elif operation == "commit":
        run_multithreaded(commit_image, inventory, username, password)
    elif operation == "clean":
        run_multithreaded(clean_disk, inventory, username, password)
    elif operation == "full-install":
        run_multithreaded(full_install_no_prompts, inventory, username, password)
    elif operation == "info" and inventory_display is True:
        print_inventory(inventory_file_path)
    elif operation == "info" and scan_for_bundle is True:
        run_multithreaded(find_bundle_mode, inventory, username, password)
    elif operation == "info" and scan_for_versions is True:
        run_multithreaded(find_ios_version, inventory, username, password)
    elif operation == "info":
        msg = "Warning: Please choose an info switch."
        print(termcolor.colored(msg, "yellow"))
    else:
        msg = f"Error: Operation not supported: {args.operation}"
        print(termcolor.colored(msg, "red"))

# EXECUTION

if __name__ == "__main__":
    main()
