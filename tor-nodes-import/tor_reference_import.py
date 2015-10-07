# quick and simple extraction of tor nodes from directory
# with insert into QRadar reference collections. 
# 
# you'll need the TorCtl python package 
# from https://gitweb.torproject.org/pytorctl.git/
# and you'll need to have tor installed on the same
# host where this script runs.
# in the config file (tor_reference_config) find common 
# paths for the Tor bundle on Windows or Mac. You'll 
# have to (un)comment and/or edit these to suit your 
# environment.
#
# author: Yossi Gilad
# edits: Rory Bray
# Forked by Justin Bollinger @Bandrel and modified to not spawn the tor proccess, but assume that it is running.  Added
#error correction incase Tor is not running.
# Added additional comments for readability


import sys
from TorCtl import TorCtl
import requests
# do as I say, not as I do;
# This is to override the untrusted certificate on Qradar.
requests.packages.urllib3.disable_warnings()

#Opens config file and parses for Qradar IP address, API key, and Control Port
config = {}
exec (open('tor_reference_config').read(), config)

qradarIpAddress = config.get('qradarIP')
qradarSecToken = config.get('qradarAPIToken')
CONTROL_PORT = config.get('CONTROL_PORT')

#Function to connect to the Tor network and download "Network Status."
#This will give a snapshot of all of the current tor nodes.
def download_network_view():
    global VIDALIA_PATH #I belive this is unneeded in this fork
    global CONTROL_PORT
    global AUTH_PASS    #I belive this is unneeded in this fork

    print "starting.."
    # open the TOR connection
    conn = TorCtl.connect(controlAddr="127.0.0.1", controlPort=CONTROL_PORT)
    all_nodes = conn.get_network_status()
    print "wrapping it up."
    conn.close()
    return all_nodes

#Function to connect to Qradar and create the framework for the reference sets that the data will be populated into"

def create_reference_set(name, elmType, ttl):
    url = 'https://' + qradarIpAddress + '/api/reference_data/sets'
    headers = {'SEC': qradarSecToken, 'Version': '4.0', 'Accept': 'application/json'}
    data = {'name': name, 'element_type': elmType, 'time_to_live': ttl, 'timeout_type': 'LAST_SEEN'}

    try:
        response = requests.get(url + '/' + name, headers=headers, verify=False)
        if response.status_code == 404:
            response = requests.post(url, headers=headers, data=data, verify=False)
            print('reference set   ' + str(name) + '      creation HTTP status: ' + str(response.status_code))
    except requests.exceptions.RequestException as exception:
        print(str(exception) + ', exiting.\n')

#Function to populate the reference sets in Qradar with the individual sets of IP addresses
def add_tor_node(set_name, ip):
    headers = {'SEC': qradarSecToken, 'Version': '4.0', 'Accept': 'application/json'}
    set_url = 'https://' + qradarIpAddress + '/api/reference_data/sets/' + set_name
    set_data = {'name': set_name, 'value': ip, 'source': 'tor_reference_import'}

    try:
        response = requests.post(set_url, headers=headers, data=set_data, verify=False)
        if response.status_code > 201:
            print('tor node ' + str(ip) + ' insertion HTTP status: ' + str(response.status_code))
    except requests.exceptions.RequestException as exception:
        print(str(exception) + ', exiting.\n')


def main():
    # check for and create reference collections in QRadar
    create_reference_set('tor_exit_nodes', 'IP', '7 days')  #(name, elmType, ttl)
    create_reference_set('tor_guard_nodes', 'IP', '7 days') #(name, elmType, ttl)
    create_reference_set('tor_intermediary_nodes', 'IP', '7 days')  #(name, elmType, ttl)
    # Guard, Exit
    #initilze variable names
    guards = set()
    exits = set()
    intermediaries = set()
    #connect to Tor and download network status
    try:
        all_nodes = download_network_view()
    except:
        print "\n[!] Verify tor service is running"
        sys.exit(1)
    for node in all_nodes:
        middle = True
        if "Guard" in node.flags:
            guards.add(node.ip)
            middle = False
        if "Exit" in node.flags:
            exits.add(node.ip)
            middle = False
        if (middle):
            intermediaries.add(node.ip)
    print('adding guard nodes ... ')
    for node in guards:
        add_tor_node('tor_guard_nodes', node)
        sys.stdout.write('.')
        sys.stdout.flush()
    print(' done.\n')
    print('adding exit nodes ... ')
    for node in exits:
        add_tor_node('tor_exit_nodes', node)
        sys.stdout.write('.')
        sys.stdout.flush()
    print(' done.\n')
    print('adding intermediary nodes ... ')
    for node in intermediaries:
        add_tor_node('tor_intermediary_nodes', node)
        sys.stdout.write('.')
        sys.stdout.flush()
    print(' done.\n')


if __name__ == "__main__":
    main()
