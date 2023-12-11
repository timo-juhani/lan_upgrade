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
import csv
import logging
import argparse
import netmiko

# FUNCTION DEFINITIONS

def run_multithreaded(function, inventory, username, password):
    """
    Use multithreading for updating multiple devicese simultaneously instead
    of in sequence. Ideally this should save a significant amount of time when
    the network is large.
    """
    print('\n---- Enable multithreading ----\n')
    config_threads_list = []
    for hostname, device in inventory.items():
        print(f"({device['name']}) Creating a thread.")
        # The name of the thread is the name of the device being configured.
        config_threads_list.append(threading.Thread(target=function,
                                                    name=hostname,
                                                    args=(device,
                                                        username,
                                                        password)))

    print('\n---- Begin running command threading ----\n')
    # Start threads. The use of .join() allows the main execution of all threads
    # finish before the main program ends.
    for thread in config_threads_list:
        thread.start()
    for thread in config_threads_list:
        thread.join()

def open_connection(device, username, password):
    """
    Open as connection to the target device. 
    Returns a ConnectHandler object or an error. 
    """
    # Try to connect to the device. Catch an authentication error and stop
    # function gracefully.
    try:
        print(f"({device['name']}) Connecting to device.")
        net_connect = netmiko.ConnectHandler(device_type=device['type'],
                                            ip=device['ipaddr'],
                                            username=username,
                                            password=password,
                                            )
        return net_connect
    except netmiko.exceptions.NetmikoAuthenticationException as err:
        print(f"({device['name']}) Error: Connection to device failed: {err}")
        return sys.exit(1)

def print_inventory(inventory_file_path):
    """
    Prints the contents of the inventory.csv to the console.
    """
    print("\nInventory:\n")
    # Print the content of the inventory file.
    with open(inventory_file_path, newline='', encoding='utf-8') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
        for row in spamreader:
            print(', '.join(row))

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
            device = {'ipaddr': device_info[0],
                      'type':   device_info[1],
                      'name':   device_info[2],
                      'target-version': device_info[3]
                      }
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
                                      read_timeout=300
                                      )
    # User Regex to find the Verified string from the CLI output.
    reg = re.compile(r'Verified')
    md5_verified = reg.findall(result)
    if md5_verified:
        print(f"({device['name']}) Success: Image verification passed.")
        result = True
    else:
        print(f"({device['name']}) Error: Image verification failed.")
        result = False
    return md5_verified

def copy_upgrade_image(net_connect, device):
    """
    Upload the image to the target device. Make sure that SCP has been enabled
    and adjust the exec-timeout.
    """
    # Make sure that SCP server has been enabled on the device.
    try:
        # SCP is enabled if not already enabled. Line exec-timeout is increased
        # to ensure the image has time to upload properly. 
        commands = [
            "ip scp server enable", 
            "line vty 0 4", 
            "exec-timeout 60"
            ]
        net_connect.send_config_set(commands)
        print(f"({device['name']}) Success: Enabled SCP server and increased",
              "exec-timeout.")
    except Exception as err:
        print(err)
        sys.exit(1)

    # Create a new SSH connection and transfer the file over SCP.
    # If the file already exist don't overwrite it.
    try:
        print(f"({device['name']}) Uploading the image now.")
        #connection = netmiko.ConnectHandler(**target_device)
        netmiko.file_transfer(
                net_connect,
                source_file=device["target-version"],
                dest_file=device["target-version"],
                file_system="flash:",
                direction="put",
                overwrite_file=False,
            )
        print (f"({device['name']}) Success: Upload completed.")

    except Exception as err:
        print (f"({device['name']}) Error: Upload failed: {err}")

def install_add(net_connect, device):
    """ 
    Using install command add the upgrade image to the device's image 
    repository.
    """
    print(f"({device['name']}) Starting to install the new image.")
    try:
        print(f"({device['name']}) Saving configuration.")
        net_connect.send_command('write memory', read_timeout=60)
        print(f"({device['name']}) Adding the new image.")
        net_connect.send_command(f"install add file flash:{device['target-version']}",
                                 read_timeout=660)
        print(f"({device['name']}) Success: The new image was added.")
    except Exception as err:
        print(f"({device['name']}) Error: Adding the image failed: {err}")
        sys.exit(1)

def verify_and_run_install_add(net_connect, device):
    """
    Add the image to the device's image repository only if the MD5 checksum is 
    ok.
    """
    md5 = check_md5(device["target-version"])
    md5_verified = verify_md5(net_connect, device, md5)

    if md5_verified:
        try:
            install_add(net_connect,device)
        except Exception as err:
            print(err)
    else:
        print(f"({device['name']}) Error: Aborting the upgrade.")

def add_image_process(device, username, password):
    """
    Adds the image to the device's image repository after running space and 
    image existence checks, copying the image to the device and verifying that 
    the MD5 checksum matches with the expected.
    """
    # Check that the device has been defined as IOS-XE device in the inventory.
    # If it's not exit the function gracefully.
    if device['type'] == 'cisco_xe':
        net_connect = open_connection(device, username, password)     
        print (f"({device['name']}) Preparing to upload image: {device['target-version']}")
        enough_space, image_exists = verify_space_iosxe(device,
                                                        net_connect,
                                                        device["target-version"]
                                                        )
        if enough_space == 'True' and image_exists == 'False':
            print(f"({device['name']}) Success: Device has space and image doesn't exist.")
            copy_upgrade_image(net_connect, device)
            verify_and_run_install_add(net_connect, device)

        elif enough_space == 'False':
            print(f"({device['name']}) Error: Not enough space. Try 'install",
                "remove inactive' on the device.")

        elif image_exists == 'True':
            print(f"({device['name']}) Target image exists.")
            verify_and_run_install_add(net_connect, device)
        net_connect.disconnect()

    else:                             
        print (f"({device['name']}) Error: Device type {device['type']} not supported.")
        sys.exit(1)

def activate_image(device, username, password):
    """ 
    Activates the new image using install activate command. The reload is auto-
    approved after activation has compeleted.
    """
    if device['type'] == 'cisco_xe':
        net_connect = open_connection(device, username, password)   
        print(f"({device['name']}) Starting to activate the new image.")
        try:
            print(f"({device['name']}) Activating the new image.")
            net_connect.send_command('install activate',
                                    read_timeout=660,
                                    expect_string=r"This operation may require a reload of the system. Do you want to proceed"
                                    )
            net_connect.send_command('y')
            print(f"({device['name']}) Success: Reload was approved.")
            print(f"({device['name']}) Success: New image activated. Reloading.")

        except Exception as err:
            print(f"({device['name']}) Error: Activating the image failed: {err}")
            sys.exit(1)

        net_connect.disconnect()

    else:
        print (f"({device['name']}) Error: Device type {device['type']} not supported.")
        sys.exit(1)

def commit_image(device, username, password):
    """ 
    Commits the new image using install commit command.
    """
    if device['type'] == 'cisco_xe':
        net_connect = open_connection(device, username, password)   
        print(f"({device['name']}) Starting to commit the new image.")
        try:
            print(f"({device['name']}) Commit the new image.")
            net_connect.send_command('install commit',
                                    read_timeout=660,
                                    )
            print(f"({device['name']}) Success: Commit complete. Device upgraded.")

        except Exception as err:
            print(f"({device['name']}) Error: commiting the image failed: {err}")
            sys.exit(1)

        net_connect.disconnect()
    else:
        print (f"({device['name']}) Error: Device type {device['type']} not supported.")
        sys.exit(1)

def clean_disk(device, username, password):
    """ 
    Clean the device flash from inactive and unused images in order to free up
    space for the upgrade.
    """
    if device['type'] == 'cisco_xe':
        net_connect = open_connection(device, username, password)   
        print(f"({device['name']}) Starting to clean the device from inactive images.")
        try:
            net_connect.send_command('install remove inactive',
                                    read_timeout=660,
                                    expect_string=r"Do you want to remove the above files"
                                    )
            net_connect.send_command('y')
            print(f"({device['name']}) Success: Clean complete.")

        except Exception as err:
            print(f"({device['name']}) Error: Clean failed: {err}")
            sys.exit(1)

        net_connect.disconnect()

    else:
        print (f"({device['name']}) Error: Device type {device['type']} not supported.")
        sys.exit(1)

# MAIN FUNCTION

def main():
    """
    Executes the program. 
    """
    # Command parser
    parser = argparse.ArgumentParser(description='LAN upgrade for devices in INSTALL mode.')
    parser.add_argument('operation', type=str,
                    help='Choose the operation to be performed: add, activate, commit, clean')
    args = parser.parse_args()

    # Start logging
    # If there is an old log file delete it first.
    if os.path.isfile('netmiko_global.log'):
        os.remove('netmiko_global.log')
    logging.basicConfig(filename='netmiko_global.log', level=logging.DEBUG)

    # Ask for administrative credentials.
    print('\n---- Credentials, Inventory and Image  ----\n')
    username = input("Management username: ")
    password = getpass.getpass(prompt ="Management password: ")

    # Inventory is hardcoded as inventory.csv for simplicity.
    # Print the inventory and then read it.
    inventory_file_path = "inventory.csv"
    print_inventory(inventory_file_path)
    inventory = read_inventory(inventory_file_path)

    # Depending on the selected positional argument run a different action
    # using multithreading against the list of devices defined in inventory.csv.
    if args.operation == "add":
        run_multithreaded(add_image_process, inventory, username, password)

    elif args.operation == "activate":
        run_multithreaded(activate_image, inventory, username, password)

    elif args.operation == "commit":
        run_multithreaded(commit_image, inventory, username, password)

    elif args.operation == "clean":
        run_multithreaded(clean_disk, inventory, username, password)
    else:
        print(f"Operation not supported: {args.operation}")

# EXECUTION

if __name__ == "__main__":
    main()
