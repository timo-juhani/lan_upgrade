"""
LAN UPGRADE FOR IOS-XE SWITCHES
Timo-Juhani Karjalainen, tkarjala@cisco.com, Cisco CX
"""

# IMPORTS

import netmiko
import os,sys,subprocess,re
from pprint import pprint
import threading
import getpass
from os.path import getsize
import csv
import logging

# FUNCTION DEFINITIONS

def print_inventory(inventory_file_path):
    print("\nInventory:\n")
    # Print the content of the inventory file. 
    with open(inventory_file_path, newline='') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
        for row in spamreader:
            print(', '.join(row))

def read_inventory(inventory_file_path):
    """
    Import the inventory of devices to be upgraded. 
    """
    devices = {}
    
    # Open the inventory file for reading the devices info.
    with open(inventory_file_path) as inventory:
        # The first line in CSV is a header which needs to be skipped.
        next(inventory)

        # After the header has been skipped devices can be loaded to the dict.
        for item in inventory:
            # Create a list of each device using comma delimeter (.csv)
            device_info = item.strip().split(',') 
            device = {'ipaddr': device_info[0],
                      'type':   device_info[1],
                      'name':   device_info[2]}
            # Each dictionary object is uniquely identified using hostname.
            devices[device["name"]] = device
    return devices

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

def verify_md5(net_connect,file,md5):
    """
    Verify that the MD5 checksum is as expected.
    Return True if image verification passes and False otherwise.
    """
    print(f"({device['name']}) Verifying MD5 hash of the image.")
    # Time out increased since verify command could take time. 
    # Note that 5 min is an overkill but safe.
    result = net_connect.send_command(f"verify /md5 flash:{file} {md5}", 
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

def cleanup(net_connect):
    """
    Removes all unused / old software images.
    """
    net_connect.send_command('install remove inactive', read_timeout=300)
    net_connect.send_command('y', expect_string='Do you want to remove the above files?')

def verify_space_iosxe(net_connect,file):
    """
    Check that there is enough space on the bootflash for the new image.
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

def copy_upgrade_image(net_connect, file, username, password):
    """
    Upload the upgrade image to the device and make sure SCP is enabled.
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
        print(f"({device['name']}) Success: Enabled SCP server and increased exec-timeout.")
    except Exception as err:
        print(err)
        exit(1)

    target_device = {
        "device_type": device["type"],
        "host": device["ipaddr"],
        "username": username,
        "password": password
    }

    # Create a new SSH connection and transfer the file over SCP.
    try:
        connection = netmiko.ConnectHandler(**target_device)
        netmiko.file_transfer(
                connection,
                source_file=file,
                dest_file=file,
                file_system="flash:",
                direction="put",
                overwrite_file=False,
            )
        print (f"({device['name']}) Success: Upload completed.")

    except Exception as err:
        print (f"({device['name']}) Error: Upload failed: {err}")

    connection.disconnect()

def software_install(net_connect,file):
    """ 
    Send the update command.
    """
    print(f"({device['name']}) Starting to install the new image.")
    try:
        print(f"({device['name']}) Saving configuration.")
        net_connect.send_command('write memory')
        print(f"({device['name']}) Activating the new image.")
        net_connect.send_command(f'install add file flash:{file} activate commit',
                                read_timeout=660,
                                expect_string=r"This operation requires a reload of the system. Do you want to proceed"
                                )
        print(f"({device['name']}) Success: The new image was activated.")
        net_connect.send_command('y')
        print(f"({device['name']}) Success: Reload was confirmed.")
        print(f"({device['name']}) Success: New image activated. Reloading.")
    except Exception as err:
        print(f"({device['name']}) Error: Upgrade failed: {err}")
        exit(1)

def command_worker(device, creds):
    # Check that the device has been defined as IOS-XE device in the inventory.
    # If it's not exit the function gracefully.
    if device['type'] == 'cisco_xe': 

        # Try to connect to the device. Catch an authentication error and stop
        # function gracefully.
        try:       
            net_connect = netmiko.ConnectHandler(device_type=device['type'], 
                                                ip=device['ipaddr'],
                                                username=creds[0], 
                                                password=creds[1],
                                                )
        except netmiko.exceptions.NetmikoAuthenticationException as err:
            print(err)
            exit(1)
        
        print(f"({device['name']}) Connecting to device.")
        print (f"({device['name']}) Preparing to upload image: {sw_image_file_path}")
        enough_space, image_exists = verify_space_iosxe(net_connect,sw_image_file_path)
        
        if enough_space == 'True' and image_exists == 'False':
            print(f"({device['name']}) Success: Device has space and image doesn't exist.")
            
            # Upload the image to the device.
            try:
                copy_upgrade_image(net_connect, sw_image_file_path, username, password)
            except Exception as err:
                print(err)
                exit(1)

            # Verify the image integrity.
            md5 = check_md5(sw_image_file_path)
            md5_verified = verify_md5(net_connect,sw_image_file_path,md5)

            if md5_verified:
                try:
                    software_install(net_connect,sw_image_file_path)
                except Exception as err:
                    print(err)
            else:
                print(f"({device['name']}) Error: Aborting the upgrade.")
                

        elif enough_space == 'False':
            print(f"({device['name']}) Error: Not enough space.")


        elif image_exists == 'True':
            print(f"({device['name']}) Target image exists.")
            md5 = check_md5(sw_image_file_path)
            md5_verified = verify_md5(net_connect,sw_image_file_path,md5)

            if md5_verified:
                try:
                    software_install(net_connect,sw_image_file_path)
                except Exception as err:
                    print(err)
            else:
                print(f"({device['name']}) Error: Aborting the upgrade.")
       
        net_connect.disconnect()

    else:                             
        print (f"({device['name']}) Error: Device type {device['type']} not supported.")
        exit(1)

        # try:
        #     software_install(net_connect,sw_image_file_path)
        # except Exception as err:
        #     print(err)

# EXECUTION

# Start logging
# If there is an old log file delete it first. 
if os.path.isfile('netmiko_global.log'):
    os.remove('netmiko_global.log')

logging.basicConfig(filename='netmiko_global.log', level=logging.DEBUG)
logger = logging.getLogger("netmiko")

#inventory_file_path = input("Inventory file path: ")
#sw_image_file_path = input("IOS-XE image Path: ")
print('\n---- Credentials, Inventory and Image  ----\n')
username = input("Management username: ")
password = getpass.getpass(prompt ="Management password: ")

inventory_file_path = "inventory.csv"
sw_image_file_path = "cat9k_lite_iosxe.17.09.04a.SPA.bin"

print_inventory(inventory_file_path)
inventory = read_inventory(inventory_file_path)
admin_credentials = (username, password)

print('\n---- Enable multithreading ----\n')
config_threads_list = []
for ipaddr,device in inventory.items():
     print(f"({device['name']}) Creating a thread.")
     config_threads_list.append(threading.Thread(target=command_worker, args=(device, admin_credentials)))

print('\n---- Begin running command threading ----\n')
for config_thread in config_threads_list:
    config_thread.start()

for config_thread in config_threads_list:
    config_thread.join()
