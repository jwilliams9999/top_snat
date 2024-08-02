#!/usr/bin/python3
import os
import requests
import influxdb_client
from influxdb_client.client.write_api import SYNCHRONOUS
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
from collections import Counter

# Disable insecure request warnings
disable_warnings(InsecureRequestWarning)

#Variable Configuration 
org = "home"
bucket = "T-Mobile"
influx_host = "10.1.1.151"
influxtoken = os.environ['INFLUXTOKEN']
fg_token = os.environ['FGTOKEN']
fg = "10.1.1.254"
fg_url = f"https://{fg}:443/api/v2/monitor/firewall/sessions"
influx_url = f"http://{influx_host}:8086"
fg_headers = {'Authorization': f'Bearer {fg_token}', 'Content-Type': 'application/json'}

def write_influx(snat, snports,field):
#write data to influxdb - snports (number of snat ports, snat - IP, field - influx field)

    client = influxdb_client.InfluxDBClient(url = influx_url, token = influxtoken, org = org)
    write_api = client.write_api(write_options=SYNCHRONOUS)
    p = influxdb_client.Point("snat_ports").tag("SNAT_IP", snat).field(field, snports) 
    write_api.write(bucket=bucket, org=org, record=p)

def api_call_fg(count,start):
    
    querystring = {"count" : count, "start" : start, "summary" : "true"}
    response = requests.get(fg_url, headers=fg_headers, params=querystring, verify=False)
    response.raise_for_status()  # raises exception when not a 2xx response
    json_resp = response.json()
    return json_resp


def main(count,start):
    snat_sessions = []

    return_results = True
    while return_results:

        fwsess = api_call_fg(count,start)
        results = fwsess['results']['details']

        if len(results) == 0:
            #unique_ips = list(set(snat_sessions))
            ipcounts = Counter(snat_sessions).most_common(10)

            for v in ipcounts:
                print (f"IP {v[0]} has used {v[1]/60416:.2%} of available snat ports")
            return_results = False

        for key in results:
            snaddr = key.get('snaddr')
            if snaddr is not None:
                snat_sessions.append(snaddr)
           
        else:
            start += 20

if __name__ == "__main__":
    main(20,0)

