#!/usr/bin/python
# Licensed under the Apache License, Version 2.0 (the "License")
# fileinfoupdater ---- a tool to trace file content changes in an appointed path.
# version 1.0
# Cheng Wu   August 30, 2019

from __future__ import print_function
from bcc import BPF
import argparse
import datetime
import os
import sys

# arguments
examples = """examples:
    ./fileinfoupdater /var/myapp/data    # trace all file closes in /var/myapp/data directory and max 8 layers subdirectories

"""
parser = argparse.ArgumentParser(
    description="Get file info when file closes",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("dir", type=str,
    help="trace this directory only with max 8 layers subdirectories")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# inode is only unique in same filesystem.
# device number of file system that args.dir belongs to. 
dev_fs = 0
dir_inode = 0
if args.dir:
    try:
        st=os.stat(args.dir)
        if st:
            dev_fs = st.st_dev
            dir_inode = st.st_ino
    except:
        print("%s doesn't exist." % args.dir)
        sys.exit(0)
else:
    print("Please appoint a directory to trace file changings.")
    sys.exit(0)

if dir_inode <= 0:
    print("Error for inode of the directory. inode %d is invalid" % dir_inode)
    sys.exit(0)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/buffer_head.h>

#define SUBDIR_MAX_DEPTH 9   //for ebpf loop limit
#define SUBDIR_PATH_LENGTH 18  //set short because of BPF stack limit. please get exact path name from inode.

struct finfo {
    u64 sz;   //file size ---8 bytes
    u64 ts;   //modified time nanosecond ---8 bytes
    u32 name_len;    //----4 bytes
    // de->d_name.name may point to de->d_iname so limit len accordingly
    char name[DNAME_INLINE_LEN+4];   // DNAME_INLINE_LEN 32. +4 for uuid filename /* 192 bytes */
    char comm[TASK_COMM_LEN];    //---- 16 bytes
    u32 pid;    //---4 bytes
    unsigned long ino; //---8 bytes
    char dirpath0[SUBDIR_PATH_LENGTH];  //----20 bytes
    char dirpath1[SUBDIR_PATH_LENGTH];  //----20 bytes
    char dirpath2[SUBDIR_PATH_LENGTH];  //----20 bytes
    char dirpath3[SUBDIR_PATH_LENGTH];  //----20 bytes
    char dirpath4[SUBDIR_PATH_LENGTH];  //----20 bytes
    char dirpath5[SUBDIR_PATH_LENGTH];  //----20 bytes
    char dirpath6[SUBDIR_PATH_LENGTH];  //----20 bytes
    char dirpath7[SUBDIR_PATH_LENGTH];  //----20 bytes
    char dirpath8[SUBDIR_PATH_LENGTH];  //----20 bytes
};

BPF_PERF_OUTPUT(events);

int kprobe__filp_close(struct pt_regs *ctx, struct file *filp, fl_owner_t id)
{
    if ( !( (filp->f_mode & FMODE_WRITE) || (filp->f_mode & FMODE_WRITE_IOCTL) ) )
        return 0;
 
    //bpf_trace_printk("f_mode=%x, %s\\n", filp->f_mode, filp->f_path.dentry->d_name.name);

    // skip operations lacking a filename, and filter operations of some shell creating empty file 
    // and fork a subprocess to reopen the file.
    struct dentry *de = filp->f_path.dentry;
    if (de->d_name.len == 0 || de->d_inode->i_size == 0)
        return 0;

    //only trace the appointed file system. aka device number.
    //shift right 12. https://elixir.bootlin.com/linux/v4.8/source/include/linux/kdev_t.h#L48
    u32 fs_devnum = new_decode_dev(de->d_inode->i_sb->s_dev);
    if (fs_devnum != DEVNUM_FILESYSTEM) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid();
    struct finfo val = {};

    struct dentry *tmpde = de;
    unsigned long dir_ino = DIR_INODE;
    struct qstr tmpd_name;

    goto FINDDIR;

    ISINDIR:
    {
        val.sz = de->d_inode->i_size;
        val.ts = (de->d_inode->i_mtime.tv_sec)*1000000000
                + de->d_inode->i_mtime.tv_nsec;  //nanosecond
        val.pid = pid;
        val.ino = de->d_inode->i_ino;

        struct qstr d_name = de->d_name;
        val.name_len = d_name.len;
        bpf_probe_read(&val.name, sizeof(val.name), d_name.name);
        bpf_get_current_comm(&val.comm, sizeof(val.comm));

        events.perf_submit(ctx, &val, sizeof(val));

        return 0;
    }


    FINDDIR:
        if (tmpde->d_parent)   //0
        {
            tmpde = tmpde->d_parent;
            if (tmpde->d_inode->i_ino == dir_ino)
                goto ISINDIR;
            tmpd_name = tmpde->d_name;
            bpf_probe_read(&val.dirpath0, sizeof(val.dirpath0), tmpd_name.name);
        }
        else
            return 0; 

        if (tmpde->d_parent)   //1
        {
            tmpde = tmpde->d_parent;
            if (tmpde->d_inode->i_ino == dir_ino)
                goto ISINDIR;
            tmpd_name = tmpde->d_name;
            bpf_probe_read(&val.dirpath1, sizeof(val.dirpath1), tmpd_name.name);
        }
        else
            return 0; 

        if (tmpde->d_parent)   //2
        {
            tmpde = tmpde->d_parent;
            if (tmpde->d_inode->i_ino == dir_ino)
                goto ISINDIR;
            tmpd_name = tmpde->d_name;
            bpf_probe_read(&val.dirpath2, sizeof(val.dirpath2), tmpd_name.name);
        }
        else
            return 0; 

        if (tmpde->d_parent)   //3
        {
            tmpde = tmpde->d_parent;
            if (tmpde->d_inode->i_ino == dir_ino)
                goto ISINDIR;
            tmpd_name = tmpde->d_name;
            bpf_probe_read(&val.dirpath3, sizeof(val.dirpath3), tmpd_name.name);
        }
        else
            return 0; 

        if (tmpde->d_parent)   //4
        {
            tmpde = tmpde->d_parent;
            if (tmpde->d_inode->i_ino == dir_ino)
                goto ISINDIR;
            tmpd_name = tmpde->d_name;
            bpf_probe_read(&val.dirpath4, sizeof(val.dirpath4), tmpd_name.name);
        }
        else
            return 0; 

        if (tmpde->d_parent)   //5
        {
            tmpde = tmpde->d_parent;
            if (tmpde->d_inode->i_ino == dir_ino)
                goto ISINDIR;
            tmpd_name = tmpde->d_name;
            bpf_probe_read(&val.dirpath5, sizeof(val.dirpath5), tmpd_name.name);
        }
        else
            return 0; 

        if (tmpde->d_parent)   //6
        {
            tmpde = tmpde->d_parent;
            if (tmpde->d_inode->i_ino == dir_ino)
                goto ISINDIR;
            tmpd_name = tmpde->d_name;
            bpf_probe_read(&val.dirpath6, sizeof(val.dirpath6), tmpd_name.name);
        }
        else
            return 0; 

        if (tmpde->d_parent)   //7
        {
            tmpde = tmpde->d_parent;
            if (tmpde->d_inode->i_ino == dir_ino)
                goto ISINDIR;
            tmpd_name = tmpde->d_name;
            bpf_probe_read(&val.dirpath7, sizeof(val.dirpath7), tmpd_name.name);
        }
        else
            return 0; 

        if (tmpde->d_parent)   //8
        {
            tmpde = tmpde->d_parent;
            if (tmpde->d_inode->i_ino == dir_ino)
                goto ISINDIR;
            tmpd_name = tmpde->d_name;
            bpf_probe_read(&val.dirpath8, sizeof(val.dirpath8), tmpd_name.name);
        }
        else
            return 0; 

        return 0;
}

"""

bpf_text = bpf_text.replace('DIR_INODE', "%d"%dir_inode if dir_inode >= 0 else '0')
bpf_text = bpf_text.replace('DEVNUM_FILESYSTEM', "%d"%dev_fs if dev_fs >= 0 else '0')

if args.ebpf:
    print(bpf_text)
    if args.ebpf:
        sys.exit(0)

# initialize BPF
b = BPF(text=bpf_text)

# header
print("Tracing file closes to show file info")
print("%-27s %-36s %15s %-27s %10s %-14s %6s %s" % 
    ("OUTPUT_TIME", "FILENAME", "BYTES", "MTIME", "INODE", "COMM", "TID", "PATH"))

SUBDIR_MAX_DEPTH = 9
def getPath(e):
    p = "./"
    for i in range(SUBDIR_MAX_DEPTH-1, -1, -1):
        subdir = eval("e.dirpath%d" % i).decode('utf-8', 'replace')
        p += (subdir+"/") if subdir else ""
    return p

DNAME_INLINE_LEN = 36    # +4 for uuid filename with 4 "-"s
def print_event(cpu, data, size):
    event = b["events"].event(data)

    name = event.name.decode('utf-8', 'replace')
    if event.name_len > DNAME_INLINE_LEN:
        name = name[:DNAME_INLINE_LEN-3] + "..."

    print("%-27s %-36s %15s %-27s %10s %-14s %6s %s" % 
    (datetime.datetime.now(), name, event.sz, datetime.datetime.fromtimestamp(event.ts/1e9), 
    event.ino, event.comm.decode('utf-8', 'replace'), event.pid, getPath(event)))

b["events"].open_perf_buffer(print_event, page_cnt=1024)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        sys.exit(0)
