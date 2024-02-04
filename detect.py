import concurrent.futures
import socket
import struct
import random
import ipaddress as ip
import os
import argparse
import subprocess
import sys

class RangeError(Exception):
    '''This exception will be raised if the the number of addresses in a provided network range is less than 2.'''

class NotPrivateError(Exception):
    '''This exception will be raised if the provided IP range is not Private.'''

class DetectionError(Exception):
    '''This exception will be raised if there is an error in automatically determing the Network settings.'''

# Determine the source host IP address (if automatic is enabled)
def get_host_ip():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0)
        try:
            # doesn't even have to be reachable
            sock.connect(('10.255.255.255', 1))
            IP = sock.getsockname()[0]
        except:
            raise DetectionError
        finally:
            sock.close()
        return ip.ip_address(IP)

# Determine the subnet mask (if automatic is enabled)
def get_subnet_mask(IP):
    # Windows OS
    if os.name == 'nt':
        win_proc = subprocess.run('ipconfig', text=True, capture_output=True)
        win_output = win_proc.stdout.splitlines()
        for line in win_output:
            if str(IP) in line:
                subnet_mask_line = (win_output[win_output.index(line) + 1])
        subnet_mask = (subnet_mask_line.split()[-1]) 
    # Linux/Mac OS
    else:
        lin_proc = subprocess.run('ifconfig', text=True, capture_output=True)
        lin_output = proc.stdout.splitlines()
        for line in lin_output:
            if str(IP) in line:
                subnet_mask = line.split()[line.split().index('netmask') + 1]
    return ip.ip_address(subnet_mask)

def progress_bar(IPs, completed, length=50):
    total = len(IPs)
    progress = len(completed)
    percent = progress / total
    progress_char = "#" * int(length * percent)
    spaces = " " * (length - len(progress_char))
    sys.stdout.write(f"\r[{progress_char}{spaces}] {int(percent * 100)}%")
    sys.stdout.flush()

# Calculate the ICMP checksum
def calculate_checksum(data):
    csum = 0
    count_to = (len(data) // 2) * 2
    for count in range(0, count_to, 2):
        this_val = data[count + 1] * 256 + data[count]
        csum = csum + this_val
        csum = csum & 0xffffffff

    if count_to < len(data):
        csum = csum + data[len(data) - 1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    result = ~csum
    result = result & 0xffff
    result = result >> 8 | (result << 8 & 0xff00)
    return result

# Send ICMP request
def send_icmp_request(dest_addr):
    try:
        progress_tracking.append(1)
        if not verbose:
            progress_bar(target_ips, progress_tracking)
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        # Generate a random ICMP identifier and sequence number
        icmp_identifier = random.randint(1, 65535)
        icmp_sequence = 1

        # ICMP header fields
        icmp_type = 8  # ICMP Echo Request
        icmp_code = 0
        icmp_checksum = 0
        icmp_data = b'Casting detect...'

        # Construct the ICMP header
        icmp_header = struct.pack("BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_sequence)
        icmp_checksum = calculate_checksum(icmp_header + icmp_data)

        # Reconstruct the ICMP header with the correct checksum
        icmp_header = struct.pack("BBHHH", icmp_type, icmp_code, socket.htons(icmp_checksum), icmp_identifier, icmp_sequence)

        # Combine the header and data to form the complete packet
        icmp_packet = icmp_header + icmp_data

        # Send the ICMP packet to the destination address
        icmp_socket.sendto(icmp_packet, (str(dest_addr), 0))
        if verbose:
            print(f"ICMP request sent to {dest_addr}")

        response = icmp_socket.recvfrom(1024)

        # Close the socket
        icmp_socket.close()
        return response

    except socket.error as e:
        print(f"Error: {e}")  

# Check whether provided IP range is valid.
def range_checks(ip_range):
    ip_range = (ip_range.split("-"))
    if len(ip_range) == 2:
        return_range = [ipaddr for ipaddr in ip.summarize_address_range(ip.ip_address(ip_range[0]), ip.ip_address(ip_range[1]))]
    elif len(ip_range) == 1:
        return_range = [ip.ip_network(ipaddr) for ipaddr in ip_range]
    else:
        raise ValueError

    total_addresses = 0
    for ipaddr in return_range:
        if ipaddr.version != 4:
            raise ValueError
        if not ipaddr.is_private:
            raise NotPrivateError
        total_addresses += ipaddr.num_addresses

    if total_addresses < 2:
        raise RangeError
    return return_range

# Instantiate argparse parser
def instantiate_argparse():
    parser = argparse.ArgumentParser(prog='detect.py', description='Standard IP scanning utility. Ranges are inclusive.')
    scan_mode = parser.add_mutually_exclusive_group(required=True)
    scan_mode.add_argument('-r', '--range', help='Specify the network range to scan: <IP/CIDR>, <IP/Netmask>, or <IP-IP>')
    scan_mode.add_argument('-a', '--automatic', help="Attempt to identify and scan the source host's network.", action="store_true")
    parser.add_argument('-v', '--verbose', help="Increase output verbosity.", action="store_true")
    return parser


# Instantiate argparse parser
parser = instantiate_argparse()

# Get argparse arguments
args = parser.parse_args()
verbose = args.verbose
automatic = args.automatic

if not automatic:
    target_range = args.range
    try:
        # Verify provided range is valid
        target_range = range_checks(target_range)
    except ValueError:
        print(f'{target_range} does not appear to be a valid IPv4 range.')
        raise SystemExit
    except RangeError:
        print(f'RangeError: You cannot scan a single IP address. Your range must contain at least 2 addresses.')
        raise SystemExit
    except NotPrivateError:
        print(f'{target_range} is not a private IPv4 range.')
        raise SystemExit
else:
    # Automatically determine network settings
    host_ip = get_host_ip()
    subnet_mask = get_subnet_mask(host_ip)
    network_address = ip.ip_address(int(host_ip) & int(subnet_mask))
    target_range = [ip.ip_network(f'{network_address}/{subnet_mask}')]


target_ips = []
print(f'Network Range(s) to scan:')
for ip_range in target_range:
    print(ip_range)
    target_ips.extend(list(ip_range))

if verbose:
    print('\nIP Addresses to Scan:')
    for ip_address in target_ips:
        print(ip_address)

print(f'\nScanning {len(target_ips)} IPs...')

# This list is appeneded to each time the send_icmp_request runs
progress_tracking = []

with concurrent.futures.ThreadPoolExecutor() as executor:
    # Utilize threading to send an ICMP request to each IP in the target network.
    f1 = executor.map(send_icmp_request, target_ips)

found_ips = []
for result in f1:
    if result[1][0] not in found_ips:
        found_ips.append(result[1][0])

print('\n\nIP addresses found:')
for ipaddr in found_ips:
    print(ipaddr)