import json
from math import log10

try:
    with open('devices.json', 'r') as myfile:
        data=myfile.read()

    with open('mapping.json', 'r') as myfile:
        maps=myfile.read()

    devices = json.loads(data)
    mapping = json.loads(maps)
except Exception as e:
    print(e)
    print("Error while opening/reading file, run airmon.py and ndump.py to make proper dump files")
    exit(0)

def dbmToDist(dbm):
    MHz=2417
    MHz=int(MHz)
    dBm=int(dbm) * -1
    FSPL = 27.55
    m = 10 ** (( FSPL - (20 * log10(MHz)) + dBm ) / 20 )
    m=round(m,2)

    return m

macmap = {}
for m in mapping:
    if("mac" in m):
        macmap[m["mac"]] = m["ipv4"]

for device in devices:
    dMac = device["bssid"]
    if(dMac in macmap):
        ip = macmap[dMac]
        print("Mac address is %s, Connected to EACCESS, IPv4: %s, approx-distance: %sm"%(dMac, ip, dbmToDist(device["dbm"])))
    else:
        pass
        # print("Mac address is %s, Not Connected"%(dMac))