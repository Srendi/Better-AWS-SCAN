import os
import socket
import ssl
import datetime
import boto3
import nmap
import subprocess
import timeit
import time
from slacker import Slacker

# Filenames
CERT_FILE = "ssl.crt"
KEY_FILE = "ssl.key"

#Path to ssl certs for various services
cert_path = {
	'http': '/etc/nginx/ssl/',
    'imap': '/etc/dovecot/ssl/',
    'pop3': '/etc/dovecot/ssl/',
}

# Command to restart various services after ssl cert update
service_restart_cmd = {
    'http' : 'service nginx restart',
    'imap' : 'service dovecot restart',
    'pop3' : 'service dovecot restart'
}

# This should be configured with relevant details
def create_self_signed_cert():
    cmd = "openssl req \
    -new \
    -newkey rsa:4096 \
    -days 365 \
    -nodes \
    -x509 \
    -subj \"/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost\" \
    -keyout ssl.key \
    -out ssl.crt"
    os.system(cmd)

#Notify out of date and updated ssl certs to slack channel
def Send2Slack(message, channel='#General'):
	slack = Slacker('SLACK-API-KEY-GOES-HERE')
	slack.chat.post_message(channel, message)

def get_ec2_ip():
    ip_list = []
    session = boto3.session.Session(
    aws_access_key_id='LESS_SECRET',
    aws_secret_access_key='SECRET',
    region_name='us-west-2')

    ec2 = session.resource('ec2')
    ec2_instances = ec2.instances.all()
    for instance in ec2_instances:
        if instance.state['Code'] == 16:
            ip_list.append(instance.public_ip_address)

    return ip_list

def portscan(ip):
    output = ""
    nmScan = nmap.PortScanner()
    nmScan.scan(ip, '0-1023')

    tic = timeit.default_timer()

    for port in nmScan[ip]['tcp']:
        cmd = "echo | openssl s_client -connect " + str(ip) + ":" + str(port) + " 2>/dev/null | openssl x509 -noout -enddate"
        result = os.system(cmd)
        if result == 0:
            if(ssl_expires_in(ip, port) == True):
                servicename = nmScan[ip]['tcp'][port]['name']
                output += ("%s certificate will be expired within 15 days, IP: %s, port: %s.\n" %(servicename, ip, port))
                create_self_signed_cert()
                scp_to_remote(ip, cert_path[servicename], CERT_FILE)
                scp_to_remote(ip, cert_path[servicename], KEY_FILE)
                time.sleep(3)
                restart_remote_service(ip, service_restart_cmd[servicename])
                output += ("%s certificate was recreated\n" %servicename)
            else:
                output += ("%s certificate status is Okay.IP: %s, port: %s.\n" %(nmScan[ip]['tcp'][port]['name'], ip, port))
    toc =  timeit.default_timer()
    sumt = toc - tic
    output += "\nTime taken to scan host " + ip + ": " + str(sumt) + " seconds.\n"
    Send2Slack(output)
#    print(output)

def ssl_expiry_datetime(ip, port):
    cmd = "echo | openssl s_client -connect " + str(ip) + ":" + str(port) + " 2>/dev/null | openssl x509 -noout -enddate"
    output = os.popen(cmd).read()
    enddate = output.split("=")[1]
    return datetime.datetime.strptime(enddate[:24], '%b %d %H:%M:%S %Y %Z')

def ssl_valid_time_remaining(hostname, port):
    """Get the number of days left in a cert's lifetime."""
    expires = ssl_expiry_datetime(hostname, port)
    return expires - datetime.datetime.utcnow()

# 2 weeks until cert expires? Better renew
def ssl_expires_in(hostname, port, buffer_days=14):
    """Check if `hostname` SSL cert expires is within `buffer_days`.

    Raises `AlreadyExpired` if the cert is past due
    """
    remaining = ssl_valid_time_remaining(hostname, port)

    # if the cert expires in less than two weeks, we should reissue it
    if remaining < datetime.timedelta(days=0):
        # cert has already expired - uhoh!
        raise AlreadyExpired("Cert expired %s days ago" % remaining.days)
    elif remaining < datetime.timedelta(days=buffer_days):
        # expires sooner than the buffer
        return True
    else:
        # everything is fine
        return False

def scp_to_remote(ip, path, filename):
    cmd = "scp -o StrictHostKeyChecking=no -i alexey.pem " + filename + " ubuntu@" + ip + ":" + path
    os.system(cmd)

def restart_remote_service(ip, restartcmd):
    cmd = "ssh -o StrictHostKeyChecking=no -i alexey.pem ubuntu@" + ip + " \'sudo " + restartcmd + "\'"
    os.system(cmd)

def main():
    ips = get_ec2_ip()
    for ip in ips:
        portscan(ip)

if __name__ == "__main__":
	main()

