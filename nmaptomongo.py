#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import argparse
import xml.dom.minidom
import pymongo

'''
Inspired from:
https://github.com/argp/nmapdb/blob/master/nmapdb.py
'''


def print_banner():
    banner = '-------------------\n' \
             '~ Nmap to MongoDB ~\n' \
             '-------------------\n'

    print(banner)


def parse_args():
    parser = argparse.ArgumentParser(description='Nmap to MongoDB')

    files_group = parser.add_mutually_exclusive_group(required=True)
    files_group.add_argument('-f', '--file', type=str, help='Nmap XML report')
    files_group.add_argument('-F', '--folder', type=str, help='Nmap XML folder reports')

    parser.add_argument('-d', '--drop', action='store_true', help='Drop existing database and create new')

    parser.add_argument('--host', type=str, default='localhost', help='MongoDB host')
    parser.add_argument('--port', type=int, default=27017, help='MongoDB port')
    parser.add_argument('--database', type=str, default='Nmap', help='MongoDB database')

    args = parser.parse_args()

    return args


def mongodb_connect(host, port, database):
    try:
        client = pymongo.MongoClient(host, port)
        client.server_info()
        db = client[database]

        return db

    except Exception as e:
        print('Cannot to connect to MongoDB')
        print(e)

        exit(1)


def mongodb_dropdatabase(host, port, database):
    try:
        client = pymongo.MongoClient(host, port)
        client.server_info()
        client.drop_database(database)

    except Exception as e:
        print('Cannot to connect to MongoDB')
        print(e)

        exit(1)


def is_nmap_report(file):
    with open(file) as f:
        for line in f:
            if line.strip() == '<!DOCTYPE nmaprun>':
                return True

    return False


def add_scan(db, scan):
    collection = db['Scans']
    collection.insert_one(scan)


def add_server(db, server):
    collection = db['Servers']
    collection.insert_one(server)


def add_service(db, service):
    collection = db['Services']
    collection.insert_one(service)


def parse_scans(nmap_xml_report, db):
    try:
        nmaprun = nmap_xml_report.getElementsByTagName("nmaprun")[0]
        args = nmaprun.getAttribute("args")

        starttimestamp = ""
        starttime = ""
        
        try:
            starttimestamp = nmaprun.getAttribute("start")
            starttime = nmaprun.getAttribute("startstr")
        except:
            pass

        type = ""
        protocol = ""
        numservices = ""
        services = ""

        try:
            scaninfo = nmaprun.getElementsByTagName("scaninfo")[0]
            type = scaninfo.getAttribute("type")
            protocol = scaninfo.getAttribute("protocol")
            numservices = scaninfo.getAttribute("numservices")
            services = scaninfo.getAttribute("services")

        except:
            pass

        endtime = ""
        endtimestamp = ""

        try:
            runstats = nmaprun.getElementsByTagName("runstats")[0]
            finished = runstats.getElementsByTagName("finished")[0]
            endtime = finished.getAttribute("startstr")
            endtimestamp = finished.getAttribute("time")
        except:
            pass

        scan = {
            'command': args,
            'starttime': starttime,
            'endtime': endtime,
            'starttimestamp': starttimestamp,
            'endtimestamp': endtimestamp,
            'type': type,
            'protocol': protocol,
            'numservices': numservices,
            'services': services,
        }

        add_scan(db, scan)
    except:
        pass


def parse_servers(nmap_xml_report, db):
    for host in nmap_xml_report.getElementsByTagName("host"):
        ip = ""
        protocol = ""
        
        try:
            address = host.getElementsByTagName("address")[0]
            ip = address.getAttribute("addr")
            protocol = address.getAttribute("addrtype")
        except:
            continue

        hostname = ""
        
        try:
            hname = host.getElementsByTagName("hostname")[0]
            hostname = hname.getAttribute("name")
        except:
            pass

        status = ""
        server_state = ""
        
        try:
            status = host.getElementsByTagName("status")[0]
            server_state = status.getAttribute("state")
        except:
            pass

        ports_open = 0
        ports_filtered = 0
        ports_closed = 0

        for port in host.getElementsByTagName("port"):
            portid = ""
            
            try:
                portid = port.getAttribute("portid")
            except:
                continue

            try:
                state = port.getElementsByTagName("state")[0]
                port_state = state.getAttribute("state")

                if port_state == 'open':
                    ports_open += 1
                elif port_state == 'filtered':
                    ports_filtered += 1
                elif port_state == 'closed':
                    ports_closed += 1
            except:
                pass

        server = {
            'ip': ip,
            'version': protocol,
            'hostname': hostname,
            'state': server_state,
            'ports_open': ports_open,
            'ports_filtered': ports_filtered,
            'ports_closed': ports_closed,
        }

        add_server(db, server)


def parse_services(nmap_xml_report, db):
    for host in nmap_xml_report.getElementsByTagName("host"):
        ip = ""
        
        try:
            address = host.getElementsByTagName("address")[0]
            ip = address.getAttribute("addr")
        except:
            continue

        for port in host.getElementsByTagName("port"):
            protocol = ""

            try:
                portid = int(port.getAttribute("portid"))
                protocol = port.getAttribute("protocol")
            except:
                continue

            port_state = ""

            try:
                state = port.getElementsByTagName("state")[0]
                port_state = state.getAttribute("state")
            except:
                pass

            name = ""
            ostype = ""
            hostname = ""
            product = ""
            version = ""
            tunnel = ""
            extrainfo = ""

            try:
                service = port.getElementsByTagName("service")[0]
                name = service.getAttribute("name")
                ostype = service.getAttribute("ostype")
                hostname = service.getAttribute("hostname")
                product = service.getAttribute("product")
                version = service.getAttribute("version")
                tunnel = service.getAttribute("tunnel")
                extrainfo = service.getAttribute("extrainfo")
            except:
                pass

            service = {
                'ip': ip,
                'port': portid,
                'state': port_state,
                'service': name,
                'hostname': hostname,
                'ostype': ostype,
                'product': product,
                'version': version,
                'tunnel': tunnel,
                'extrainfo': extrainfo,
            }

            add_service(db, service)


if __name__ == '__main__':
    args = parse_args()

    print_banner()

    reports = []
    if args.file:
        reports.append(args.file)
    elif args.folder:
        for file in os.listdir(args.folder):
            if is_nmap_report(os.path.join(args.folder, file)):
                reports.append(os.path.join(args.folder, file))

    if args.drop:
        ans = input('Drop database \"{}\" [y/N]: '.format(args.database))
        if ans.lower() == 'y':
            mongodb_dropdatabase(args.host, args.port, args.database)
            print('Database \"{}\" dropped\n'.format(args.database))

    db = mongodb_connect(args.host, args.port, args.database)

    parsing_error_files = []

    print('File(s) parsed:')

    for report in reports:
        
        try:
            nmap_xml_report = xml.dom.minidom.parse(report)

            parse_scans(nmap_xml_report, db)
            parse_servers(nmap_xml_report, db)
            parse_services(nmap_xml_report, db)

            print(' - {}'.format(report))
            
        except:
            parsing_error_files.append(report)
        
    if len(parsing_error_files) != 0:
        print('\nUnable to parse file(s):')
        for report in parsing_error_files:
            print(' - {}'.format(report))

    print('\nNmap scans imported to database \"{}\"\n'.format(args.database))
