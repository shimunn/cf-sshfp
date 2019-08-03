#/usr/bin/env python3



import CloudFlare
import sys,os
import subprocess
import socket

def hashes(hostname):
    out = subprocess.check_output(['ssh-keygen', '-r', hostname])
    if out:
        res = []
        for line in out.split("\n"):
            if len(line) > 0:
                (hostname, _, pr_tpe, key_tpe, hash_tpe, hash_val) = line.split(" ")
                res.append({'hostname': hostname, 'pr': pr_tpe, 'key_type': key_tpe, 'hash_type': hash_tpe, 'hash': hash_val})
        return res
    return None

def add_cf(email, zone, token, hostname, hashes):
    zone_name = zone

    cf = CloudFlare.CloudFlare(email, token)

    # query for the zone name and expect only one value back
    try:
        zones = cf.zones.get(params = {'name':zone_name,'per_page':101})
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/zones.get %d %s - api call failed' % (e, e))
    except Exception as e:
        exit('/zones.get - %s - api call failed' % (e))

    if len(zones) == 0:
        exit('No zones found')

    # extract the zone_id which is needed to process that zone
    zone = zones[0]
    zone_id = zone['id']

    # request the DNS records from that zone
    params = {'name': hostname, 'match':'all'}
    try:
        dns_records = cf.zones.dns_records.get(zone_id, params=params)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/zones/dns_records.get %d %s - api call failed' % (e, e))

    # print the results - first the zone name
    print zone_id, zone_name

    # then all the DNS records for that zone
    for dns_record in dns_records:
        r_name = dns_record['name']
        r_type = dns_record['type']
        r_value = dns_record['content']
        r_id = dns_record['id']
        if not r_type == 'SSHFP':
            continue
        (key_tpe, hash_tpe, hash_val) = r_value.replace("\t", " ").replace('  ', ' ').replace('  ', ' ').replace('  ', ' ').replace('  ', ' ').replace('  ', ' ').strip().split(" ")
        for h in hashes:
            if h["hash"] == hash_val:
                hashes.remove(h)
        print '\t', key_tpe, hash_val
    new_records = []
    for h in hashes:
        new_records.append({
            "name": hostname,
            "type": h["pr"],
            "content": "%s %s %s" % (h["key_type"],h["hash_type"], h["hash"]),
            "ttl": 1,
            "proxied": False,
            "data": {
                "algorithm": h["hash_type"],
                "type": h["key_type"],
                "fingerprint": h["hash"]
            }
            })
    try:
        for dns_record in new_records:
            print dns_record
            r = cf.zones.dns_records.post(zone_id, data=dns_record)
        print("Added %d records" % len(new_records))
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/zones/dns_records.post %d %s - api call failed' % (e, e))        
    exit(0)

if __name__ == '__main__':
    if not (len(sys.argv) == 4 and "CF_API_KEY" in os.environ or len(sys.argv) == 5):
        print("Required arguments: <email> <zone> <hostname> [token]")
        sys.exit(1)
    email = sys.argv[1]
    zone = sys.argv[2]
    hostname = sys.argv[3]
    token = os.environ["CF_API_KEY"] if "CF_API_KEY" in os.environ else sys.argv[4]
    hashes = hashes(hostname)
    if not hashes:
        print "Failed to generate dns records, make sure /etc/ssh/ssh_host_*.pub is readable by the current user"
        sys.exit(1)
    add_cf(email, zone, token, hostname, hashes)
