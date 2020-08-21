#!/usr/bin/env python3
from utils.parse_args import parse_args
from datetime import datetime
from src.net_sniff import NetSniff
from src.read_pcap import ReadPCAP
from src.write_pcap import WritePCAP
from colored import fg, attr
from sys import exit
from platform import system
from subprocess import run, PIPE
from random import randint

SYSTEM = system()

if __name__ == "__main__":
    if SYSTEM == "Linux":
        user = run(["whoami"], stdout=PIPE, stderr=PIPE)
        user = user.stdout.decode("utf-8").replace("\n", "")
        if user != "root":
            print("[%sERROR%s] %s MUST BE RAN AS `root`" % (fg(9), attr(0), __file__))
            exit(1)

    args = parse_args()
    args = {
        "live": args.live_mode,
        "interf": args.interf,
        "filter": args.filter,
        "count": args.count,
        "promis": args.promis_off,
        "read": args.read_mode,
        "rfile": args.rfile,
        "hex": args.hex_dump,
        "pkt-cnt": args.packet_count,
        "no-prn": args.no_print,
        "rc": args.read_count,
        "src-ip-count": args.source_ip_count,
        "dst-ip-count": args.destination_ip_count,
        "ip-count": args.ip_count,
        "before": args.before,
        "after": args.after,
        "time-range": args.time_range,
        "start-date":args.start_date,
        "end-date": args.end_date,
        "date-range": args.date_range,
        "write": args.write_mode,
        "wfile": args.wfile,
        "src-ip": args.source_ip,
        "not-src-ip":args.not_source_ip,
        "dst-ip": args.destination_ip,
        "not-dst-ip": args.not_destination_ip,
        "src-port": args.source_port,
        "not-src-port": args.not_source_port,
        "dst-port": args.destination_port,
        "not-dst-port": args.not_destination_port,
        "src-mac": args.source_mac,
        "not-src-mac": args.not_source_mac,
        "dst-mac": args.destination_mac,
        "not-dst-mac": args.not_destination_mac,
        "tcp": args.filter_tcp,
        "not-tcp": args.not_filter_tcp,
        "udp": args.filter_udp,
        "not-udp": args.not_filter_udp,
        "icmp": args.filter_icmp,
        "not-icmp": args.not_filter_icmp,
        "arp": args.filter_arp,
        "not-arp": args.not_filter_arp,
        "dns": args.filter_dns,
        "not-dns": args.not_filter_dns,
        "tcp-flags": args.tcp_flags,
        "le": args.len_less_equal,
        "ge": args.len_greater_equal,
        "len-eq": args.len_equal,
        "ttl-eq": args.ttl_equal,
        "sum": args.summary,
        "json": args.json,
    }

    if args["live"]:
        if not args["interf"]:
            print("[ %sATTENTION%s ] an interface, `-i`, must be specified" % (fg(202), attr(0)))
            exit(1)
        capture = NetSniff(args["interf"], args["filter"], args["count"], args["promis"])
        print("[ %sATTENTION%s ] PLEASE WAIT A SECOND OR TWO FOR A RESPONSE" % (fg(202), attr(0)))
        capture.capture()

    elif args["read"]:
        if args["rfile"]:
            read_obj = ReadPCAP(
                args["rfile"], args["hex"], args["src-ip"], args["not-src-ip"], args["dst-ip"], 
                args["not-dst-ip"], args["src-port"], args["not-src-port"], 
                args["dst-port"], args["not-dst-port"], args["src-mac"], 
                args["not-src-mac"], args["dst-mac"], args["not-dst-mac"],
                args["tcp"], args["not-tcp"], args["udp"], args["not-udp"],
                args["icmp"], args["not-icmp"], args["pkt-cnt"]
            )
            read_obj.read(count=args["rc"])

            if args["src-ip"]:
                read_obj.filter_src_ip()
            elif args["not-src-ip"]:
                read_obj.filter_not_src_ip()
            elif args["dst-ip"]:
                read_obj.filter_dst_ip()
            elif args["not-dst-ip"]:
                read_obj.filter_not_dst_ip()
            elif args["src-port"]:
                read_obj.filter_src_port()
            elif args["not-src-port"]:
                read_obj.filter_not_src_port()
            elif args["dst-port"]:
                read_obj.filter_dst_port()
            elif args["not-dst-port"]:
                read_obj.filter_not_dst_port()
            elif args["src-mac"]:
                read_obj.filter_src_mac()
            elif args["not-src-mac"]:
                read_obj.filter_not_src_mac()
            elif args["dst-mac"]:
                read_obj.filter_dst_mac()
            elif args["not-dst-mac"]:
                read_obj.filter_not_dst_mac()
            elif args["tcp"]:
                read_obj.filter_tcp()
            elif args["not-tcp"]:
                read_obj.filter_not_tcp()
            elif args["udp"]:
                read_obj.filter_udp()
            elif args["not-udp"]:
                read_obj.filter_not_udp()
            elif args["icmp"]:
                read_obj.filter_icmp()
            elif args["not-icmp"]:
                read_obj.filter_not_icmp()
            elif args["arp"]:
                read_obj.filter_arp()
            elif args["not-arp"]:
                read_obj.filter_not_arp()
            elif args["dns"]:
                read_obj.filter_dns()
            elif args["not-dns"]:
                read_obj.filter_not_dns()
            elif args["tcp-flags"]:
                read_obj.filter_tcp_flags(args["tcp-flags"])
            elif args["le"]:
                read_obj.len_le_eq(args["le"])
            elif args["ge"]:
                read_obj.len_gr_eq(args["ge"])
            elif args["len-eq"]:
                read_obj.len_eq(args["len-eq"])
            elif args["ttl-eq"]:
                read_obj.ttl_eq(args["ttl-eq"])
            elif args["before"]:
                read_obj.before(args["before"])
            elif args["after"]:
                read_obj.after(args["after"])
            elif args["time-range"]:
                read_obj.time_range(args["time-range"])
            elif args["start-date"]:
                read_obj.start_date(args["start-date"])
            elif args["end-date"]:
                read_obj.end_date(args["end-date"])
            elif args ["date-range"]:
                read_obj.date_range(args["date-range"])
            else:
                read_obj.no_filter(args["no-prn"])

            if args["src-ip-count"] or args["dst-ip-count"] or args["ip-count"]:
                print("-"*95)
                if args["src-ip-count"]:
                    for ip in args["src-ip-count"]:
                        src_ip_count = read_obj.src_ip_count(ip)
                        print(
                            f"[ + ] %s%s{ip}%s appeared as the source IP address {src_ip_count} times" 
                            % (fg(randint(1, 230)), attr("bold"), attr("reset"))
                        )
                if args["dst-ip-count"]:
                    for ip in args["dst-ip-count"]:
                        dst_ip_count = read_obj.dst_ip_count(ip)
                        print(
                            f"[ + ] %s%s{ip}%s appeared as the destination IP address {dst_ip_count} times"
                            % (fg(randint(1, 230)), attr("bold"), attr("reset"))
                        )
                if args["ip-count"]:
                    for ip in args["ip-count"]:
                        ip_count = read_obj.ip_count(ip)
                        print(
                            f"[ + ] %s%s{ip}%s appeared either as the source or destination IP address {ip_count} times"
                            % (fg(randint(1, 230)), attr("bold"), attr("reset"))
                        )

            if args["sum"]:
                read_obj.summary()
                read_obj.packet_count()

            if args["json"]:
                read_obj.to_json(args["json"])
                print("[ %sSUCCESS%s ] SUMMARY JSON FILE CREATED" % (fg(50), attr(0)))
            
            if args["pkt-cnt"]:
                pkt_count = read_obj.packet_count()
                print("[ %s+%s ] Number of packets in PCAP: " % (fg(50), attr(0)), pkt_count)
        else:
            print(
                "[ %sERROR%s ] MUST PROVIDE `-r` ARGUMENTS FOR READ MODE"
                % (fg(9), attr(0))
            )
            exit(1)

    elif args["write"]:
        if not args["interf"]:
            print("[ %sATTENTION%s ] an interface, `-i`, must be specified" % (fg(202), attr(0)))
            exit(1)
        if args["wfile"]:
            write_obj = WritePCAP(
                args["wfile"], args["interf"], args["filter"], args["count"], args["promis"],
                args["src-ip"], args["not-src-ip"], args["dst-ip"], args["not-dst-ip"],
                args["src-port"], args["not-src-port"], args["dst-port"], args["not-dst-port"],
                args["src-mac"], args["not-src-mac"], args["dst-mac"], args["not-dst-mac"],
                args["tcp"], args["not-tcp"], args["udp"], args["not-udp"], args["icmp"],
                args["not-icmp"]
            )
        else:
            print(
                "[ %sERROR%s ] MUST PROVIDE `-w` ARGUMENT FOR WRITE MODE"
                % (fg(9), attr(0))
            )
            exit(1)     

        if args["count"]:
            if args["src-ip"]:
                write_obj.filter_src_ip()
            elif args["not-src-ip"]:
                write_obj.filter_not_src_ip()
            elif args["dst-ip"]:
                write_obj.filter_dst_ip()
            elif args["not-dst-ip"]:
                write_obj.filter_not_dst_ip()
            elif args["src-port"]:
                write_obj.filter_src_port()
            elif args["not-src-port"]:
                write_obj.filter_not_src_port()
            elif args["dst-port"]:
                write_obj.filter_dst_port()
            elif args["not-dst-port"]:
                write_obj.filter_not_dst_port()
            elif args["src-mac"]:
                write_obj.filter_src_mac()
            elif args["not-src-mac"]:
                write_obj.filter_not_src_mac()
            elif args["dst-mac"]:
                write_obj.filter_dst_mac()
            elif args["not-dst-mac"]:
                write_obj.filter_not_dst_mac()
            elif args["tcp"]:
                write_obj.filter_tcp()
            elif args["not-tcp"]:
                write_obj.filter_not_tcp()
            elif args["udp"]:
                write_obj.filter_udp()
            elif args["not-udp"]:
                write_obj.filter_not_udp()
            elif args["icmp"]:
                write_obj.filter_icmp()
            elif args["not-icmp"]:
                write_obj.filter_not_icmp()
            elif args["arp"]:
                write_obj.filter_arp()
            elif args["not-arp"]:
                write_obj.filter_not_arp()
            elif args["dns"]:
                write_obj.filter_dns()
            elif args["not-dns"]:
                write_obj.filter_not_dns()
            elif args["tcp-flags"]:
                write_obj.filter_tcp_flags(args["tcp-flags"])
            elif args["le"]:
                write_obj.len_le_eq(args["le"])
            elif args["ge"]:
                write_obj.len_gr_eq(args["ge"])
            elif args["len-eq"]:
                write_obj.len_eq(args["len-eq"])
            elif args["ttl-eq"]:
                write_obj.ttl_eq(args["ttl-eq"])
            else:
                write_obj.no_filter()

            if args["sum"]:
                write_obj.summary()
                
            if args["json"]:
                write_obj.to_json(args["json"])
                print("[ %sSUCCESS%s ] SUMMARY JSON FILE CREATED" % (fg(50), attr(0)))
        else:
            print(
                "[ %sATTENTION%s ] MUST PROVIDE `-c` ARGUMENT FOR WRITE MODE"
                % (fg(202), attr(0))
            )
    else:
        print(
            "[ %sERROR%s ] MUST PROVIDE A MODE OF OPERATION: -live, -read, or -write"
            % (fg(9), attr(0))
        )
