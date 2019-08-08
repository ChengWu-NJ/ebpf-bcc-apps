#!/usr/bin/python3
# wucheng     August 8, 2019
# sockmetrics.py --- collect sock communication info among hosts
# version 0.9
# two methods to output results:
# 1. to screen
# 2. to TDengine, a kind of structured time series db
# please run ./sockmetrics -h to get help
# This program bases on https://github.com/iovisor/bcc
# Licensed Apache-2.0

#from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep, strftime
from subprocess import call
from collections import namedtuple, defaultdict
import os
import json
import taos
import datetime

# arguments
def range_check(string):
    value = int(string)
    if value < 1 or value > 600:
        msg = "value must be 1 ~ 600, got %d" % (value,)
        raise argparse.ArgumentTypeError(msg)
    return value

def positive_check(string):
    value = int(string)
    if value < 1:
        msg = "value must be stricly positive, got %d" % (value,)
        raise argparse.ArgumentTypeError(msg)
    return value

examples = """examples:
    ./sockmetrics --conf_file='/etc/sockmetrics.conf'   # input all sock trace data into tsdb configured in conf_file
    ./sockmetrics           # trace Sock send/recv by host on screen
    ./sockmetrics -p 181    # only trace PID 181 on screen
"""
parser = argparse.ArgumentParser(
    description="Summarize Sock send/recv throughput by host",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("--conf_file", 
    help="this argument points the configure file, and is exclusive and discards other arguments ")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=1, type=range_check,
    help="output interval, in seconds (default 1), range 1 ~ 600")
parser.add_argument("count", nargs="?", default=-1, type=positive_check,
    help="number of the records with the top recerived bytes to output per interval")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

def get_arguments_from_conf_file(conf_file):
    with open(conf_file, 'r') as jsonfile:
        _d = json.load(jsonfile)
        if _d.get("dbhost") and _d.get("database") \
                and _d.get("user") and _d.get("password"):
            return _d
        else:
            raise Exception("conf_file %s is invalid."%conf_file)
            
conf_dict = None
if args.conf_file and os.stat(args.conf_file):
    conf_dict = get_arguments_from_conf_file(args.conf_file)
    args.pid = None
    _interval = conf_dict.get('interval')
    if _interval is not None and _interval > 0 and _interval <= 600:
        args.interval = _interval
    else:
        args.interval = 1
    _count = conf_dict.get('count')
    if _count is not None and _count > 0:
        args.count = _count
    else:
        args.count = -1

debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/net.h>
#include <uapi/linux/ip.h>
#include <linux/ip.h>

struct ipv4_key_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u16 socktype;
};
BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);

struct ipv6_key_t {
    u32 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
    u16 socktype;
};
BPF_HASH(ipv6_send_bytes, struct ipv6_key_t);
BPF_HASH(ipv6_recv_bytes, struct ipv6_key_t);

//static int kprobe__packet_snd(struct pt_regs *ctx, struct socket *sock, 
//                struct msghdr *msg, size_t len)
int kprobe__inet_sendmsg(struct pt_regs *ctx, struct socket *sock, struct msghdr *msg, size_t size)
{
//bpf_trace_printk("entry inet_sendmsg now. \\n");
    u32 pid = bpf_get_current_pid_tgid();
    FILTER
    struct sock *sk = sock->sk;
    u16 dport = 0, family = sk->__sk_common.skc_family;
//bpf_trace_printk("inet_sendmsg got family %d, and protocol is %d\\n", family, sk->__sk_common.skc_prot);

    if (family == AF_INET && sk->__sk_common.skc_rcv_saddr != sk->__sk_common.skc_daddr) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_key.socktype = sock->type;
        ipv4_send_bytes.increment(ipv4_key, size);

    }
    
    if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        __builtin_memcpy(&ipv6_key.saddr,
            sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32, sizeof(ipv6_key.saddr));
        __builtin_memcpy(&ipv6_key.daddr,
            sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32, sizeof(ipv6_key.daddr));

        if (ipv6_key.saddr == ipv6_key.daddr)
            return 0;

        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        ipv6_key.socktype = sock->type;
        ipv6_send_bytes.increment(ipv6_key, size);
    }
    // else drop

    return 0;
}


int kprobe__inet_recvmsg(struct pt_regs *ctx, struct socket *sock, struct msghdr *msg, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    struct sock *sk = sock->sk;

    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero = 0;

  //  bpf_trace_printk("inet_recvmsg got family %d\\n", family);
    if (size <= 0) 
        return 0;

    if (family == AF_INET && sk->__sk_common.skc_rcv_saddr != sk->__sk_common.skc_daddr) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_key.socktype = sock->type;
        ipv4_recv_bytes.increment(ipv4_key,size);

    } 

    if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        __builtin_memcpy(&ipv6_key.saddr,
            sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32, sizeof(ipv6_key.saddr));
        __builtin_memcpy(&ipv6_key.daddr,
            sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32, sizeof(ipv6_key.daddr)); 

        if (ipv6_key.saddr == ipv6_key.daddr)
            return 0;

        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        ipv6_key.socktype = sock->type;
        ipv6_recv_bytes.increment(ipv6_key, size);
    }
   // else drop

    return 0;
}


"""

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

SockSessionKey = namedtuple('SockSession', ['pid', 'laddr', 'lport', 'daddr', 'dport', 'socktype'])

def pid_to_comm(pid):
    try:
        comm = open("/proc/%d/comm" % pid, "r").read().rstrip()
        return comm
    except IOError:
        return str(pid)

def _to_socktype(type): #https://elixir.bootlin.com/linux/latest/source/include/linux/net.h#L60
    return "TCP" if type==1 else "UDP" if type==2 else "Other"

def get_ipv4_session_key(k):
    return SockSessionKey(pid=k.pid,
                         laddr=inet_ntop(AF_INET, pack("I", k.saddr)),
                         lport=k.lport,
                         daddr=inet_ntop(AF_INET, pack("I", k.daddr)),
                         dport=k.dport,
                         socktype=k.socktype)

def get_ipv6_session_key(k):
    return SockSessionKey(pid=k.pid,
                         laddr=inet_ntop(AF_INET6, k.saddr),
                         lport=k.lport,
                         daddr=inet_ntop(AF_INET6, k.daddr),
                         dport=k.dport,
                         socktype=k.socktype)

def getdbconnection(cnfdict):
    _conn = taos.connect(host=cnfdict["dbhost"], user=cnfdict["user"], 
            password=cnfdict["password"], database=cnfdict["database"])
    print(_conn._host)
    return _conn

def sqlexecute(cursor, sqltext):
    #continue when network error, etc.
    try:
        cursor.execute(sqltext)
        return True
    except:
        return False

def createtables(cursor):
    _ipv4_ready = sqlexecute(cursor,
        """create table if not exists ipv4_metrics (
            epoch timestamp, 
            pid int, 
            comm binary(40), 
            type int, 
            laddr binary(15), 
            lport int, 
            raddr binary(15), 
            rport int, 
            rx_byte bigint, 
            tx_byte bigint,
            interval_sum smallint)""")
    _ipv6_ready = sqlexecute(cursor,
        """create table if not exists ipv6_metrics (
            epoch timestamp, 
            pid int, 
            comm binary(40), 
            type int, 
            laddr6 binary(39), 
            lport int, 
            raddr6 binary(39), 
            rport int, 
            rx_byte bigint, 
            tx_byte bigint,
            interval_sum smallint)""")
    if _ipv4_ready and _ipv6_ready:
        return True
    else:
        return False


# initialize BPF
b = BPF(text=bpf_text)
"""
if b.get_kprobe_functions(b"netif_receive_skb"):
    b.attach_kprobe(event="netif_receive_skb", fn_name="trace_netif_receive_skb")
else:
    print("ERROR: netif_receive_skb() kernel function not found or traceable. "
        "Older kernel versions not supported.")
    exit()
"""
ipv4_send_bytes = b["ipv4_send_bytes"]
ipv4_recv_bytes = b["ipv4_recv_bytes"]
ipv6_send_bytes = b["ipv6_send_bytes"]
ipv6_recv_bytes = b["ipv6_recv_bytes"]

# tsdb if conf_file is set
if conf_dict:
    output_db = True
else:
    output_db =False

if output_db:
    conn = getdbconnection(conf_dict)
    csr = conn.cursor()
    i_reconnect = 0
    if not createtables(csr):
        raise(Exception("Something wrong when create tables."))

  
print('Tracing... Output every %s secs. Hit Ctrl-C to end' % args.interval)
print('Collected data will input to tsdb...')

# output
exiting = False
while not exiting:
    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = True
        if output_db:
            csr.close()
            conn.close()

    # reset dbconnect. continue when network error, etc.
    
    if output_db and i_reconnect >= 100:
        i_reconnect = 0
        try:
            csr.close()
            conn.close()
            conn = getdbconnection(conf_dict)
            csr = conn.cursor()
        except:
            pass

    # IPv4: build dict of all seen keys
    ipv4_throughput = defaultdict(lambda: [0, 0])
    for k, v in ipv4_send_bytes.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][0] = v.value
    ipv4_send_bytes.clear()

    for k, v in ipv4_recv_bytes.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][1] = v.value
    ipv4_recv_bytes.clear()

    if not output_db and ipv4_throughput:
        print("%-6s %-12s %-6s %-21s %-21s %9s %9s" % ("PID", "COMM", "TYPE",
            "LADDR", "RADDR", "RX_Byte", "TX_Byte"))

    # output
    i = 0
    for k, (send_bytes, recv_bytes) in (ipv4_throughput.items()
                if args.count==-1 else sorted(ipv4_throughput.items(),
                                              key=lambda kv: sum(kv[1]),
                                              reverse=True)):
        if args.count > 0 and i >= args.count:
            break
        if output_db:
            sqlexecute(csr, """insert into 
                ipv4_metrics (epoch, pid, comm, type, laddr, lport, raddr, rport, rx_byte, tx_byte, interval_sum)
                values ('%s', %d, '%s', %d, '%s', %d, '%s', %d, %d, %d, %d)"""
                % (datetime.datetime.now(), k.pid, pid_to_comm(k.pid), k.socktype,
                    k.laddr, k.lport, k.daddr, k.dport, recv_bytes, send_bytes, args.interval) )
        else:
            print("%-6d %-12.12s %-6.6s %-21s %-21s %9d %9d" % (k.pid,
                pid_to_comm(k.pid), _to_socktype(k.socktype),
                k.laddr + ":" + str(k.lport),
                k.daddr + ":" + str(k.dport),
                recv_bytes, send_bytes))
        i += 1

    # IPv6: build dict of all seen keys
    ipv6_throughput = defaultdict(lambda: [0, 0])
    for k, v in ipv6_send_bytes.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][0] = v.value
    ipv6_send_bytes.clear()

    for k, v in ipv6_recv_bytes.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][1] = v.value
    ipv6_recv_bytes.clear()

    if ipv6_throughput:
        # more than 80 chars, sadly.
        print("\n%-6s %-12s %-6s %-32s %-32s %9s %9s" % ("PID", "COMM", "TYPE",
            "LADDR6", "RADDR6", "RX_Byte", "TX_Byte"))

    # output
    i = 0
    for k, (send_bytes, recv_bytes) in (ipv6_throughput.items()
                if args.count==-1 else sorted(ipv6_throughput.items(),
                                              key=lambda kv: sum(kv[1]),
                                              reverse=True)):
        if args.count > 0 and i >= args.count:
            break
        if output_db:
            sqlexecute(csr, """insert into 
                ipv6_metrics (epoch, pid, comm, type, laddr6, lport, raddr6, rport, rx_byte, tx_byte, interval_sum)
                values ('%s', %d, '%s', %d, '%s', %d, '%s', %d, %d, %d, %d)"""
                % (datetime.datetime.now(), k.pid, pid_to_comm(k.pid), k.socktype,
                    k.laddr, k.lport, k.daddr, k.dport, recv_bytes, send_bytes, args.interval) )
        else:
            print("%-6d %-12.12s %-6.6s %-32s %-32s %9d %9d" % (k.pid,
                pid_to_comm(k.pid), _to_socktype(k.socktype),
                k.laddr + ":" + str(k.lport),
                k.daddr + ":" + str(k.dport),
                recv_bytes, send_bytes))
        i += 1
    if output_db:
        i_reconnect += 1
