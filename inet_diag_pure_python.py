# -*- coding:utf-8 -*-
# author web<liuyangc33@gmail.com>

# use inet_diag_req (versoin 1), tested with kernel 2.6.32

import os
import math
import struct
import ctypes
import socket

# const define
NETLINK_SOCK_DIAG = 4
TCPDIAG_GETSOCK = 18  # linux/inet_diag.h
TCP_LISTEN = 1 << 10
INET_DIAG_NOCOOKIE = ctypes.c_uint(~0)

NLMSG_ERROR = 0x0002
NLMSG_DONE = 0x0003

NLM_F_REQUEST = 1  # It is request message.
NLM_F_ROOT = 0x100  # specify tree    root
NLM_F_MATCH = 0x200  # return all matching
NLM_F_DUMP = (NLM_F_ROOT | NLM_F_MATCH)


# C struct define
class NLMSGHDR(ctypes.Structure):
    _fields_ = [
        ("nlmsg_len", ctypes.c_uint32),
        ("nlmsg_type", ctypes.c_uint16),
        ("nlmsg_flags", ctypes.c_uint16),
        ("nlmsg_seq", ctypes.c_uint32),
        ("nlmsg_pid", ctypes.c_uint32)
    ]


class NLMSGERR(ctypes.Structure):
    _fields_ = [
        ("error", ctypes.c_int),
        ("msg", NLMSGHDR)
    ]


class INET_DIAG_SOCKETED(ctypes.Structure):
    _fields_ = [
        ("idiag_sport", ctypes.c_uint16.__ctype_be__),
        ("idiag_dport", ctypes.c_uint16.__ctype_be__),
        ("idiag_src", ctypes.c_uint32.__ctype_be__ * 4),
        ("idiag_dst", ctypes.c_uint32.__ctype_be__ * 4),
        ("idiag_if", ctypes.c_uint32),
        ("idiag_cookie", ctypes.c_uint32 * 2),
    ]


class INET_DIAG_REQ(ctypes.Structure):
    _fields_ = [
        ("idiag_family", ctypes.c_uint8),
        ("idiag_src_len", ctypes.c_uint8),
        ("idiag_dst_len", ctypes.c_uint8),
        ("idiag_ext", ctypes.c_uint8),
        ("id", INET_DIAG_SOCKETED),
        ("idiag_states", ctypes.c_uint32),
        ("idiag_dbs", ctypes.c_uint32)
    ]


class INET_DIAG_MSG(ctypes.Structure):
    _fields_ = [
        ("idiag_family", ctypes.c_uint8),
        ("idiag_state", ctypes.c_uint8),
        ("idiag_timer", ctypes.c_uint8),
        ("idiag_retrans", ctypes.c_uint8),
        ("id", INET_DIAG_SOCKETED),
        ("idiag_expires", ctypes.c_uint32),
        ("idiag_rqueue", ctypes.c_uint32),
        ("idiag_wqueue", ctypes.c_uint32),
        ("idiag_uid", ctypes.c_uint32),
        ("idiag_inode", ctypes.c_uint32),
    ]


class NLREQUEST(ctypes.Structure):
    """ Netlink request """
    _fields_ = [
        ("nlh", NLMSGHDR),
        ("req", INET_DIAG_REQ)
    ]


class NetLink(object):
    def __init__(self):
        self._sock = None

    def _init_socket(self):
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_SOCK_DIAG)
        sock.bind((os.getpid(), 0))
        self._sock = sock

    def close(self):
        self._sock.close()
        self._sock = None

    def gen_nl_request(self, tcp_states):
        inet_diag_sockid = INET_DIAG_SOCKETED(
            idiag_cookie=(INET_DIAG_NOCOOKIE, INET_DIAG_NOCOOKIE))

        nlmsghdr = NLMSGHDR(
            nlmsg_len=ctypes.sizeof(NLREQUEST),
            nlmsg_type=TCPDIAG_GETSOCK,
            nlmsg_flags=NLM_F_REQUEST | NLM_F_DUMP,
            nlmsg_seq=1,
            nlmsg_pid=os.getpid())

        req = INET_DIAG_REQ(
            idiag_family=socket.AF_INET,
            id=inet_diag_sockid,
            idiag_states=tcp_states)

        return NLREQUEST(nlmsghdr, req)

    def send(self, nlreq):
        if not self._sock:
            self._init_socket()
        self._sock.sendto(nlreq, (0, 0))

    def recv(self):
        result = []
        nlh = NLMSGHDR()

        finished = False
        while not finished:
            # A big buffer to avoid truncating message.
            # The size is borrowed from libnetlink.
            buff, addr = self._sock.recvfrom(16384)
            offset = 0
            while (offset + ctypes.sizeof(NLMSGHDR)) <= len(buff):
                ctypes.memmove(ctypes.addressof(nlh), buff[offset:], ctypes.sizeof(nlh))
                offset_payload = offset + align(ctypes.sizeof(NLMSGHDR))

                if nlh.nlmsg_type == NLMSG_ERROR:
                    err = NLMSGERR()
                    if (len(buff) - offset_payload) < ctypes.sizeof(NLMSGERR):
                        raise ValueError("message truncated")
                    ctypes.memmove(ctypes.addressof(NLMSGERR), buff[offset_payload:], ctypes.sizeof(NLMSGERR))
                    raise ValueError("message error: {0}".format(os.strerror(-err.error)))

                elif nlh.nlmsg_type == NLMSG_DONE:
                    finished = True
                    break
                else:
                    payload_start = offset_payload
                    payload_end = offset_payload + nlh.nlmsg_len - (offset_payload - offset)
                    payload = buff[payload_start:payload_end]
                    result.append(parse_diag_msg(payload))
                    # Move to next message
                    offset += align(nlh.nlmsg_len)

        self.close()
        return tuple(result)


def align(size):
    return int(math.ceil(size / 4)) * 4


def parse_diag_msg(data):
    # only parse src and src port in struct inet_diag_msg
    message = INET_DIAG_MSG()
    ctypes.memmove(ctypes.addressof(message), data, ctypes.sizeof(message))
    # Alternatively, in Python 2.7+/3.3+,  you can use lib ipaddress to
    # convert this 32-bit packed binary to a ip string
    little_end_src = struct.pack('!I', message.id.idiag_src[0])
    ip = socket.inet_ntoa(little_end_src)
    return ip, message.id.idiag_sport


if __name__ == "__main__":
    netlink = NetLink()
    nlreq = netlink.gen_nl_request(TCP_LISTEN)
    netlink.send(nlreq)
    print netlink.recv()
