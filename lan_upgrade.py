#!/usr/bin/env python
"""
LAN UPGRADE FOR IOS-XE SWITCHES
timo-juhani, tkarjala@cisco.com
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
import socket
import netmiko
import pyfiglet
import pandas
import termcolor


# CLASS DEFINITIONS

class CustomFormatter(logging.Formatter):
    """
    Formatter class for setting the message formats and colors used by the logger. 
    """
    grey = '\x1b[38;21m'
    blue = '\x1b[38;5;39m'
    yellow = '\x1b[38;5;226m'
    red = '\x1b[38;5;196m'
    bold_red = '\x1b[31;1m'
    reset = '\x1b[0m'
    format = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# FUNCTION DEFINITIONS

def exception_handler(func):
    """
    Decorator to catch device exceptions. 
    Returns the function or exits the program if an exception occurs.
    """
    def inner_function(device, username, password, *args, **kwargs):
        try:
            return func(device, username, password, *args, **kwargs)
        except netmiko.exceptions.NetmikoAuthenticationException as err:
            logging.error("%s - Authentication failed. - %s", device["name"], err)
            return sys.exit(1)
        except netmiko.exceptions.NetmikoTimeoutException as err:
            logging.error("%s - Connection timeout. - %s", device["name"], err)
            return sys.exit(1)
        except socket.error as err:
            logging.error("%s - Connection was dropped. - %s", device["name"], err)
            return sys.exit(1)
    return inner_function

def exception_handler_inventory(func):
    """
    Decorator to catch inventory file exceptions. 
    Returns the function or exits the program if an exception occurs.
    """
    def inner_function(inventory_file, *args, **kwargs):
        try:
            return func(inventory_file, *args, **kwargs)
        except FileNotFoundError as err:
            logging.error("Inventory file not found: %s. - %s", inventory_file, err)
            return sys.exit(1)
    return inner_function

def create_parser():
    """
    Create a parser that the user can use to provide program arguments.
    Returns the parser.
    """
    parser = argparse.ArgumentParser(description="Shell application for running upgrades.")
    parser.add_argument("operation", type=str, help= """Choose the operation to be performed: info,
                        add, activate, commit, clean, full-install""")
    parser.add_argument("-u", "--username", type=str, help="Username of the admin user.")
    parser.add_argument("-p", "--password", type=str, help="Password of the admin user.")
    parser.add_argument("-I", "--inventorymode", help="INVENTORY mode: enable.",
                        action="store_true")
    parser.add_argument("-i", "--inventory", help="Display inventory.", action="store_true")
    parser.add_argument("-b", "--bundle", help="Display devices in bundle mode.",
                        action="store_true")
    parser.add_argument("-s", "--scansoftware", help="Display software versions.",
                        action="store_true")
    parser.add_argument("-r", "--reachability", help="Check for control connections.",
                        action="store_true")
    parser.add_argument("-c", "--convert", help="Convert from BUNDLE to INSTALL mode",
                        action="store_true")
    parser.add_argument("-d", "--debug", help="Run in debug mode", action="store_true")
    parser.add_argument("-H", "--hostname", type=str, help="HOST mode: hostname.")
    parser.add_argument("-O", "--os", type=str, help="HOST mode: OS type (cisco_xe).")
    parser.add_argument("-S", "--software", type=str, help="HOST mode: Software image (*.bin).")
    parser.add_argument("-T", "--target", type=str, help="HOST mode: IP address.")
    return parser

def create_banner():
    """
    Create a banner to show when the program is executed.
    """
    banner = pyfiglet.figlet_format("LAN Upgrade", font="slant")
    warning = "Warning: Device upgrade is a disruptive operation!"
    print("\n")
    print(termcolor.colored(banner, "magenta", attrs=["bold"]))
    print("\n")
    print(termcolor.colored(warning, "yellow"))
    print("\n")

def run_multithreaded(function, inventory, username, password):
    """
    Use multithreading for updating multiple devicese simultaneously instead
    of in sequence. Ideally this should save a significant amount of time even when the network 
    consists of some devices.
    """
    config_threads_list = []
    for hostname, device in inventory.items():
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
    logging.info("%s - Establishing connection.", device["name"])
    net_connect = netmiko.ConnectHandler(device_type=device['type'], ip=device['ipaddr'],
                                        username=username, password=password)
    return net_connect

@exception_handler
def check_control_connection(device, username, password):
    """
    Checks the reachability to the device(s).
    """
    logging.info("%s - Checking control connection.", device["name"])
    logging.info("%s - Pinging the device.", device["name"])

    # Run a simple OS command to ping the device once. Send the stdout to bin. 
    ping_response = os.system(f"ping -c 1 {device['ipaddr']} > /dev/null 2>&1")

    # If the response is null the device responded. Else the ping test failed and the program stops.
    if ping_response == 0:
        logging.info("%s - Responds to ping.", device["name"])
    else:
        logging.error("%s - Doesn't respond to ping.", device["name"])
        sys.exit(1)

    # After ping test has succeeded try to open an SSH connection to the target device.
    # If exception_handler doesn't capture an error notify the user that the control connections is
    # ok.
    logging.info("%s - Opening a control connection with SSH.", device["name"])
    net_connect = open_connection(device, username, password)
    net_connect.disconnect()
    logging.info("%s - Control connection OK!", device["name"])

@exception_handler_inventory
def print_inventory(inventory_file):
    """
    Prints the contents of the inventory.csv to the console.
    """
    print("\nInventory:\n")
    # Print the content of the inventory file.
    with open(inventory_file, newline='', encoding='utf-8') as csvfile:
        print(pandas.read_csv(csvfile))
        print("\n")

@exception_handler_inventory
def read_inventory(inventory_file):
    """
    Reads the inventory.csv file.
    Returns a dictionary that contains information about each device defined by
    the user.
    """
    devices = {}
    # Open the inventory file for reading the devices info.
    with open(inventory_file, encoding='utf-8') as inventory:
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

def choose_mode(args, device, inventory_file):
    """
    Based on the arguments provided (or not) the program enters in either INVENTORY or HOST mode. 
    Returns inventory as a result - either based on inventory.csv or CLI arguments for a single
    host. 
    """
    # The program enters HOST mode only if all CLI arguments have been provided by the user.
    if (args.hostname is not None and args.os is not None and args.software is not None
        and args.target is not None):
        logging.info("Entering HOST mode.")
        inventory = device
        return inventory
    # Even if one of the CLI arguments is missing the execution stops there and the user will be
    # notified.
    if (args.hostname is None or args.os is None or args.software is None
          or args.target is None) and args.inventorymode is False:
        logging.error("HOST mode requires hostname, os, software and target flags.")
        return sys.exit(1)

    inventory = read_inventory(inventory_file)
    return inventory

def check_image_exists(device, net_connect,file):
    """
    Check whether the target .bin exists on the device already.
    Return boolean True if it's already there on flash and False if not. 
    """
    logging.info("%s - Checking if image exists already.", device["name"])
    # Check what files are on the disk.
    result = net_connect.send_command("show flash:")
    # Using Regex parse if the software binary is already on the disk.
    reg = re.compile(fr"{file}")
    exist = reg.findall(result)
    if exist:
        return True
    else:
        return False

def check_flash_space(device, net_connect,file):
    """
    Check that there is enough space on the bootflash for the new image.
    Returns True if it fits or False if there isn't enough space.
    """
    logging.info("%s - Checking disk space.", device["name"])
    # Check what files are on the disk.
    result = net_connect.send_command("show flash:")
    # Using Regex parse how many bytes are free.
    reg = re.compile(r'(\d+)\sbytes\savailable')
    space = int(reg.findall(result)[0])
    # Then calculate the local file's size. The one that is on this project's root folder.
    f_size = os.path.getsize(file)
    # If there is more space than the size of the file the function returns true.
    if space >= f_size:
        return True
    # If less space that the size of the file return false.
    if space < f_size:
        return False

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
    logging.info("Expected upgrade image hash is: %s.", md5)
    return md5

def verify_md5(net_connect, device, md5):
    """
    Verify that the MD5 checksum is as expected.
    Return True if image verification passes and False otherwise.
    """
    logging.info("%s - Verifying MD5 hash of the image.", device["name"])
    # Time out increased since verify command could take time.
    # Note that 5 min is an overkill but safe.
    result = net_connect.send_command(f"verify /md5 flash:{device['target-version']} {md5}",
                                      read_timeout=300)
    # User Regex to find the Verified string from the CLI output.
    reg = re.compile(r'Verified')
    md5_verified = reg.findall(result)
    if md5_verified:
        logging.info("%s - Image verification passed.", device["name"])
        result = True
    else:
        logging.error("%s - Image verification failed.", device["name"])
        result = False
    return md5_verified

def enable_scp(net_connect, device):
    """
    Enable SCP server on the target device.
    """
    #try:
    # SCP is enabled if not already enabled. Line exec-timeout is increased
    # to ensure the image has time to upload properly.
    logging.info("%s - Enabling SCP server now.", device["name"])
    commands = [
        "ip scp server enable", 
        "line vty 0 4", 
        "exec-timeout 60"
        ]
    net_connect.send_config_set(commands)
    logging.info("%s - Enabled SCP server and exec-timeout increased.", device["name"])

def copy_upgrade_image(net_connect, device):
    """
    Upload the image to the target device using SCP file transfer.
    """
    # Create a new SSH connection and transfer the file over SCP.
    # If the file already exist don't overwrite it.
    logging.info("%s - Uploading the image now.", device["name"])
    netmiko.file_transfer(net_connect, source_file=device["target-version"],
                          dest_file=device["target-version"], file_system="flash:", direction="put",
                          overwrite_file=False)
    logging.info("%s - Upload completed.", device["name"])

def install_add(net_connect, device):
    """ 
    Using install command add the upgrade image to the device's image 
    repository.
    """
    logging.info("%s - Starting to install the new image.", device["name"])
    logging.info("%s - Saving configuration.", device["name"])
    net_connect.send_command('write memory', read_timeout=60)
    logging.info("%s - Adding the new image.", device["name"])
    net_connect.send_command(f"install add file flash:{device['target-version']}", read_timeout=660)
    logging.info("%s - The new image was added.", device["name"])

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
        logging.error("%s - Aborting the upgrade.", device["name"])
        sys.exit(1)

@exception_handler
def find_ios_version(device, username, password):
    """
    Scans the device(s) for IOS version.
    Prints the version and if the device needs to be upgraded.
    """
    if device['type'] == 'cisco_xe':
        # Parse the version out from filename. First remove the common suffix.
        target_version = device["target-version"].removesuffix(".SPA.bin")
        # Then match the version using Regex and therefore get rid of the prefix of the filename.
        # The match is the first list item.
        reg = re.compile(r"\S{1,2}[.]\S{1,2}[.]\S{1,3}$")
        target_version = reg.findall(target_version)[0]
        # Get show version to find running version
        net_connect = open_connection(device, username, password)
        logging.info("%s - Get 'show version'", device["name"])
        output = net_connect.send_command('show version', read_timeout=60)
        net_connect.disconnect()
        # Find the right line from command output. It starts with Cisco IOS XE Software.
        for line in output.split("\n"):
            if 'Cisco IOS XE Software' in line:
                # Keep only the version and get rid of everything else.
                running_version = line.split(",")[1].removeprefix(" Version ")
                # If the running version is same as the target no upgrade required.
                # If not inform the user that an upgrade is required.
                if running_version == target_version:
                    logging.info("%s - Running %s, Target %s -> OK!", device["name"],
                                 running_version, target_version)
                    return True
                else:
                    logging.warning("%s - Running %s, Target %s -> UPGRADE!", device["name"],
                                    running_version, target_version)
                    return False
    else:
        logging.error("%s - Device type %s not supported.", device['name'], device['type'])
        sys.exit(1)

@exception_handler
def add_image_process(device, username, password):
    """
    Adds the image to the device's image repository.
    """

    # Check if the upgrade is needed in the first place.
    no_upgrade_needed = find_ios_version(device, username, password)

    # If it's needed and desired go forward.
    if device["type"] == "cisco_xe" and device["upgrade"] == "yes" and no_upgrade_needed is False:
        net_connect = open_connection(device, username, password)

        # Check if the image exists already.
        image_exists = check_image_exists(device, net_connect, device["target-version"])

        # If the image exists we can skip the file transfer and just verify and install the image.
        if image_exists is True:
            logging.info("%s - Target image exists.", device["name"])
            verify_and_run_install_add(net_connect, device)

        # If the image doesn't exists transfer it to the target if there is enough space for it.
        elif image_exists is False:
            logging.info("%s - Target image doesn't exist.", device["name"])
            logging.info("%s - Checking if there is enough space for image upload.", device["name"])
            enough_space = check_flash_space(device, net_connect, device["target-version"])

            if enough_space is True:
                # If there is enough disk space the target image can be safely moved to the device
                # for installation.
                logging.info("%s - Device has enough space for the image.", device["name"])
                enable_scp(net_connect, device)
                copy_upgrade_image(net_connect, device)
                verify_and_run_install_add(net_connect, device)
            elif enough_space is False:
                logging.error("%s - Not enough space. Try 'install remove inactive.'",
                              device["name"])
        net_connect.disconnect()

    # If the upgrade is needed but the device is not flagged for upgrade notify the user and exit.
    elif device["upgrade"] == "no" and no_upgrade_needed is False:
        logging.warning("%s - Needs upgrade but not flagged to be upgraded (see inventory.csv).",
                        device["name"])
        sys.exit(1)

    # If upgrade is not needed notify the user and exit.
    elif no_upgrade_needed is True:
        logging.info("%s - No need to upgrade. Already in target version.", device["name"])
        sys.exit(1)

    # In case the inventory contains unsupported device types notify the user and exit.
    else:
        logging.error("%s - Device type %s not supported.", device['name'], device['type'])
        sys.exit(1)

@exception_handler
def activate_image(device, username, password):
    """ 
    Activates the new image using install activate command. The reload is auto-
    approved after activation has compeleted.
    """
    # Upgrade only devices that are flagged for upgrade in inventory.csv (INVENTORY mode). In HOST
    # mode it's assumed that the device will be updated.
    if device['type'] == 'cisco_xe' and device["upgrade"] == "yes":
        net_connect = open_connection(device, username, password)
        logging.info("%s - Starting to activate the new image.", device["name"])
        logging.info("%s - Activate the new image.", device["name"])
        # Moves the target version to activate but not commited stage. The activation requires a
        # reload which is auto-approved by the script. Actication should be done during maintenance
        # windows to avoid service loss. Timer set to 11 min to give time for slower switches.
        msg = r"This operation may require a reload of the system. Do you want to proceed"
        net_connect.send_command('install activate', read_timeout=660,
                                expect_string=msg
                                )
        net_connect.send_command('y')
        logging.info("%s - New image activated and reload approved. Reloading now!", device["name"])
        net_connect.disconnect()
    elif device["upgrade"] == "no":
        logging.warning("%s - Not flagged to be upgraded (see inventory.csv).", device["name"])
        sys.exit(1)
    else:
        logging.error("%s - Device type %s not supported.", device['name'], device['type'])
        sys.exit(1)

@exception_handler
def commit_image(device, username, password):
    """ 
    Commits the new image using install commit command.
    """
    # Upgrade only devices that are flagged for upgrade in inventory.csv (INVENTORY mode). In HOST
    # mode it's assumed that the device will be updated.
    if device['type'] == 'cisco_xe' and device["upgrade"] == "yes":
        net_connect = open_connection(device, username, password)
        logging.info("%s - Starting to commit the new image.", device["name"])
        logging.info("%s - Commit the new image.", device["name"])
        # The last step in the staged upgrade process. After commit the new version shows as the
        # # active committed version.
        net_connect.send_command('install commit', read_timeout=660)
        logging.info("%s - Commit complete. Device upgraded.", device["name"])
        net_connect.disconnect()
    elif device["upgrade"] == "no":
        logging.warning("%s - Not flagged to be upgraded (see inventory.csv).", device["name"])
        sys.exit(1)
    else:
        logging.error("%s - Device type %s not supported.", device['name'], device['type'])
        sys.exit(1)

@exception_handler
def clean_disk(device, username, password):
    """ 
    Clean the device flash from inactive and unused images in order to free up space for the 
    upgrade. 
    """
    if device['type'] == 'cisco_xe':
        net_connect = open_connection(device, username, password)
        # Sends the remove command to device. Setting a generous timer to allow time for slower
        # switches to do their thing. Since the script has to cover logic remove command accepts
        # any type of prompt as a result. After executing the remove command the script determines
        # what to do next by checking the current prompt on the device. If the device asks for
        # confirmation it decides that images can be removed and auto-approves the removal. In any
        # other condition it assumes that there is nothing to clean since.
        logging.info("%s - Starting to clean the device from inactive images.", device["name"])
        net_connect.send_command('install remove inactive', read_timeout=660,
                                expect_string=r"[\s\S]+")

        # The list for important Netmiko channel outputs that are the program is at look out for.
        prompts = [
            "[y/n]",
            "Cleanup directory found, already in progress",
            "Nothing to clean"
        ]

        # Scan the Netmiko channel to find one of the prompt items that are required to determine
        # the next step in the process. Save the channel output and the previous output.
        found_prompt = False
        while found_prompt is False:
            channel = net_connect.read_channel()
            for prompt in prompts:
                if prompt in str(channel):
                    found_prompt = True
            last_channel = channel

        # Decision tree based on the channel outputs. Normally the program just wants to acknowledge
        # the request to proceed. However, it turns out IOS-XE needs a bit of error handling to
        # stabilize the program and ensure success.
        if "Do you want to remove the above files" in last_channel:
            net_connect.send_command('y')
            logging.info("%s - Clean complete.", device["name"])
        elif "Cleanup directory found, already in progress" in channel:
            logging.error("%s - Clean already in progress. Please wait and try again.",
                          device["name"])
        elif "Nothing to clean" in channel:
            logging.info("%s - Nothing to clean", device["name"])
        net_connect.disconnect()
    else:
        logging.error("%s Device type %s not supported.", device['name'], device['type'])
        sys.exit(1)

@exception_handler
def full_install_no_prompts(device, username, password):
    """ 
    Adds, activate and commits the image using install commands without raising prompts for the 
    user. It enables a one step install for users that doesn't require a phased approach with add, 
    activate and commit commands. 
    """
    # Upgrade only devices that are flagged for upgrade in inventory.csv (INVENTORY mode). In HOST
    # mode it's assumed that the device will be updated.
    if device["type"] == "cisco_xe" and device["upgrade"] == "yes":
        net_connect = open_connection(device, username, password)
        # Configuration must be saved unless saved already prior to upgrade.
        logging.info("%s - Saving configuration.", device["name"])
        net_connect.send_command('write memory', read_timeout=60)
        logging.info("%s - Starting full install without prompts.", device["name"])
        # One-shot command to run thorugh the entire installation without asking any confirmation
        # from the user. This is handy when the upgraded device doesn't require staged upgrade. An
        # example could be lab equipment or non-critical production upgrades. The timeout is raised
        # to 15 min in order to cater for slower switches such as Cat 9200L.
        cmd = f"install add file flash:{device['target-version']} activate commit prompt-level none"
        net_connect.send_command(cmd, read_timeout=900)
        logging.info("%s - Full install complete. Device rebooting.", device["name"])
        net_connect.disconnect()
    elif device["upgrade"] == "no":
        logging.warning("%s - Not flagged to be upgraded (see inventory.csv).", device["name"])
        sys.exit(1)
    else:
        logging.error("%s - Device type %s not supported.", device['name'], device['type'])
        sys.exit(1)

@exception_handler
def find_bundle_mode(device, username, password):
    """
    Scans the device configuration to find whether the device is in bundle mode.
    Returns true if in bundle mode or false if not. 
    """
    if device['type'] == 'cisco_xe':
        net_connect = open_connection(device, username, password)
        logging.info("%s - Get 'show version'", device["name"])
        output = net_connect.send_command('show version', read_timeout=60)
        net_connect.disconnect()
        # Find if either BUNDLE or INSTALL exists in the command output. Both of these are
        # indicators of the installation mode used for the device. Both modes require different
        # approach or conversion when upgrading which is the reason why it must be known by the user
        # before upgrades are started. Give a warning to the user when BUNDLE mode is used. And
        # although there's nothing wrong with that Cisco recommends using INSTALL mode therefore
        # this program also relies on INSTALL mode only.
        if "BUNDLE" in output:
            logging.warning("%s - Runs in BUNDLE mode. Convert to INSTALL before upgrade.",
                            device["name"])
            return True
        elif "INSTALL" in output:
            logging.info("%s - Runs in INSTALL mode.", device["name"])
            return False
        else:
            logging.error("%s - Can't determine whether runs in INSTALL or BUNDLE mode." +
                          " Manual check required.")
            return False
    else:
        logging.error("%s - Device type %s not supported.", device['name'], device['type'])
        sys.exit(1)

@exception_handler
def convert_from_bundle_to_install(device, username, password):
    """
    Converts the device from bundle mode to install mode. 
    """
    in_bundle_mode = find_bundle_mode(device, username, password)
    current_image_is_target = find_ios_version(device, username, password)
    if in_bundle_mode is True and current_image_is_target is True:
        # If the device is in bundle mode and current image is the same as target image (which is a
        # requirement for conversion).
        logging.info("%s - Starting the conversion process.", device["name"])
        net_connect = open_connection(device, username, password)
        logging.info("%s - Finding if packages.conf exists on flash.", device["name"])
        output = net_connect.send_command('dir flash:packages.conf', read_timeout=60)

        # If packages.conf is not around: point the boot system to packages.conf and expand the .bin
        # file with one-shot install command. This reboots the device in INSTALL mode with the same
        # version as it was running with.
        if "Error opening flash:/packages.conf (No such file or directory)" in output:
            logging.info("%s - packages.conf doesn't exist on flash.", device["name"])
            commands = ["no boot system",
                        "boot system flash:packages.conf"]
            logging.info("%s - Removing the old boot system configuration.", device["name"])
            logging.info("%s - Setting the boot variable to flash:packages.conf", device["name"])
            net_connect.send_config_set(commands)
            logging.info("%s - Saving configuration.", device["name"])
            net_connect.send_command("write memory")
            logging.info("%s - Running one-shot install command.", device["name"])
            full_install_no_prompts(device, username, password)

        # Else it's safe to assume that .bin has been already expanded on flash and the only thing
        # left to do is to just point the boot system to packages.conf and reboot the device.
        else:
            logging.info("%s - packages.conf exists on flash.", device["name"])
            commands = ["no boot system",
                        "boot system flash:packages.conf"]
            logging.info("%s - Removing the old boot system configuration.", device["name"])
            logging.info("%s - Setting the boot variable to flash:packages.conf", device["name"])
            net_connect.send_config_set(commands)
            logging.info("%s - Saving configuration.", device["name"])
            net_connect.send_command("write memory")
            logging.info("%s - Rebooting the device.", device["name"])
            net_connect.send_command("reload", expect_string="confirm")
            net_connect.send_command("\n")
        net_connect.disconnect()
    elif current_image_is_target is False:
        logging.error("%s - Target must be the current version to convert.", device["name"])
        sys.exit(1)
    else:
        logging.error("%s - Doesn't run in BUNDLE mode. No actions required.", device["name"])
        sys.exit(1)

def operation_logic(args, inventory, username, password, inventory_file):
    """
    Chooses an operation based on arguments provided by the user.
    """
    # Add image to devices image repository
    if args.operation == "add":
        run_multithreaded(add_image_process, inventory, username, password)

    # Activate image to devices image repository. Note: this requires a reload.
    elif args.operation == "activate":
        run_multithreaded(activate_image, inventory, username, password)

    # Commit the image as the new running image.
    elif args.operation == "commit":
        run_multithreaded(commit_image, inventory, username, password)

    # Remove all packages that are not currently in use. Helps to clean up the disk before upgrade.
    elif args.operation == "clean":
        run_multithreaded(clean_disk, inventory, username, password)

    # One-shot installation that doesn't ask for permissions. Add, activate, commit, reload.
    elif args.operation == "full-install":
        run_multithreaded(full_install_no_prompts, inventory, username, password)

    # Conversion from BUNDLE mode to INSTALL mode.
    elif args.operation == "convert":
        run_multithreaded(convert_from_bundle_to_install, inventory, username, password)

    # Info switch that shows the device inventory (.csv).
    elif args.operation == "info" and args.inventory is True:
        print_inventory(inventory_file)

    # Info switch that goes to device(s) to check if it's in INSTALL or BUNDLE mode.
    elif args.operation == "info" and args.bundle is True:
        run_multithreaded(find_bundle_mode, inventory, username, password)

    # Info switch that finds the running IOS version and compares it to the target version.
    elif args.operation == "info" and args.scansoftware is True:
        run_multithreaded(find_ios_version, inventory, username, password)

    # Info switch that checks the condition of control connection to device(s)
    elif args.operation == "info" and args.reachability is True:
        run_multithreaded(check_control_connection, inventory, username, password)

    # Info operaton requires a switch -> give a pointer to the user.
    elif args.operation == "info":
        logging.warning("Please choose an info switch.")

    # For unsupported operations.
    else:
        logging.error("Operation not supported: %s", args.operation)

# MAIN FUNCTION

def main():
    """
    Executes the main program. 
    """

    # Print the welcome banner.
    create_banner()

    # Create the command parser.
    parser = create_parser()
    args = parser.parse_args()

    # Start logging. If there is an old log file delete it first.
    log_file = "application.log"
    if os.path.isfile(log_file):
        os.remove(log_file)

    # Logging saves and shows the same content to a log file and stdout, respectively.
    # The program can be run in debug mode which the user selects using an CLI argument "debug".
    # Upon selection the argument is marked as True by the program and the logic below increases
    # the global logging accuracy all the way to DEBUG messages. If not selected the program follows
    # the default behavior of showing only INFO and above messages.
    file_handler = logging.FileHandler(filename=log_file)
    stdout_handler = logging.StreamHandler(stream=sys.stdout)
    stdout_handler.setFormatter(CustomFormatter())
    handlers = [file_handler, stdout_handler]

    if args.debug is True:
        logging.basicConfig(
            level=logging.DEBUG,
            format='[%(asctime)s] %(levelname)s - %(message)s',
            handlers=handlers
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s - %(message)s',
            handlers=handlers
        )

    logging.getLogger("application")

    # Save arguments provided by the user to local variables.
    username = args.username
    password = args.password

    # Create a dictionary for HOST mode.
    device = {args.hostname: {"ipaddr": args.target, "type": args.os, "name": args.hostname,
              "target-version": args.software, "upgrade": "yes"}}

    # Ask for administrative credentials if those haven't been provided as arguments.
    if args.username is None:
        username = input("Management username: ")
    if args.password is None:
        password = getpass.getpass(prompt ="Management password: ")

    # Inventory is hardcoded as inventory.csv for simplicity.
    inventory_file = "inventory.csv"

    # Run the program in either HOST or INVENTORY mode.
    # HOST gets a single device parameters as arguments whereas INVENTORY is just read from .csv.
    inventory = choose_mode(args, device, inventory_file)

    # Depending on the selected positional argument run a different action using multithreading
    # against the list of devices defined in inventory.csv.
    operation_logic(args, inventory, username, password, inventory_file)

# EXECUTION

if __name__ == "__main__":
    main()
