import nmap
import io, json

target = '172.16.48.0/20'

print("Scanning network, this might take some time.")

scanner = nmap.PortScanner()
scanner.scan(target, arguments='-sn', sudo=True)
 
hosts = []
for host in scanner.all_hosts():
    addresses = scanner[host]['addresses']
    hosts.append(addresses)

jsonstr1 = json.dumps(hosts, indent=4)
with io.open('mapping.json', 'w', encoding='utf-8') as f:
    f.write(jsonstr1)

print("Saved data to mapping.json!")