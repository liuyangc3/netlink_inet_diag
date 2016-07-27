/*
 * Python C API wrapper for inet_diag.c, tested with kernel 2.6.32
 * author web<liuyangc33@gmail.com> 
 *
 * refs: http://git.sipsolutions.net/?p=pynl80211.git;a=blob;f=netlink.c
 *       https://github.com/hulkamania/python-inet_diag/
 * 
 * compile: 
 *     gcc py_netlink.c -fPIC -I/usr/include/python2.6 -shared -o _netlink.so
 *
 * use in Python:
 * import os, socket
 * import _netlink
 * sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 4)
 * sock.bind((os.getpid(), 0))
 * fd = sock.fileno()
 * _netlink.send(fd, 1<<10)
 * result = _netlink.recv(fd)
 * print result
 */

#include <Python.h>

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>


enum {
    SS_UNKNOWN,
    SS_ESTABLISHED,
    SS_SYN_SENT,
    SS_SYN_RECV,
    SS_FIN_WAIT1,
    SS_FIN_WAIT2,
    SS_TIME_WAIT,
    SS_CLOSE,
    SS_CLOSE_WAIT,
    SS_LAST_ACK,
    SS_LISTEN,
    SS_CLOSING,
    SS_MAX
};

#define SS_ALL ((1 << SS_MAX) - 1)

static const int default_states = SS_ALL & ~((1 << SS_LISTEN) |
                                             (1 << SS_CLOSE) |
                                             (1 << SS_TIME_WAIT) |
                                             (1 << SS_SYN_RECV));

static PyObject *nlbind(PyObject *self, PyObject *args, PyObject *kwargs) {
    int fd, ret = 0;
    static char *kwlist[] = {"fd", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "i", kwlist, &fd))
        return NULL;

    struct sockaddr_nl nladdr = {
            .nl_family = AF_NETLINK,
            .nl_pid    = getpid(),
    };

    if (bind(fd, (struct sockaddr *) &nladdr, sizeof(nladdr))) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    Py_RETURN_NONE;
}


/*
 * states: TCP states
 *
 * */
static PyObject *nlsend(PyObject *self, PyObject *args, PyObject *kwargs) {
    int fd;
    int states = default_states;
    static char *kwlist[] = {"fd", "states", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ii", kwlist, &fd, &states))
        return NULL;

    struct sockaddr_nl nladdr = {
            .nl_family = AF_NETLINK,
            .nl_pid    = 0,         /* kernel */
    };

    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req r;
    } req = {
            .nlh = {
                    .nlmsg_len   = sizeof(req),
                    .nlmsg_type  = TCPDIAG_GETSOCK,
                    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                    .nlmsg_seq   = 1,
            },
            .r = {
                    .idiag_family = AF_INET,
                    .idiag_states = states,
                    .id = {
                            .idiag_cookie[0] = INET_DIAG_NOCOOKIE,
                            .idiag_cookie[1] = INET_DIAG_NOCOOKIE,
                    },
            },
    };

    struct iovec iov[1] = {
            [0] = {
                    .iov_base = &req,
                    .iov_len  = sizeof(req),
            },
    };

    struct msghdr msg = {
            .msg_name    = &nladdr,
            .msg_namelen = sizeof(nladdr),
            .msg_iov     = iov,
            .msg_iovlen  = 1,
    };

    if (sendmsg(fd, &msg, 0) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *nlrecv(PyObject *self, PyObject *args) {
    int fd, len;
    size_t buff_len = 16384;

    if (!PyArg_ParseTuple(args, "i", &fd))
        return NULL;

    char *buff = (char *) calloc(buff_len, sizeof(char));
    if (!buff) {
        PyErr_NoMemory();
        return NULL;
    }

    struct sockaddr_nl nladdr = {
            .nl_family = AF_NETLINK,
            .nl_pid    = 0,
    };

    struct iovec iov[1] = {
            [0] = {
                    .iov_base = buff,
                    .iov_len  = buff_len,
            },
    };

    struct msghdr msg = {
            .msg_name    = &nladdr,
            .msg_namelen = sizeof(nladdr),
            .msg_iov     = iov,
            .msg_iovlen  = 1,
    };


    PyObject *list;
    Py_Initialize();
    list = PyList_New(0);
    char ipbuf[48];

    while (1) {
        if ((len = recvmsg(fd, &msg, 0)) < 0) {
            close(fd);
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }

        struct nlmsghdr *h = (struct nlmsghdr *) buff;

        while (NLMSG_OK(h, len)) {
            if (h->nlmsg_type == NLMSG_DONE)
                goto out;

            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                    PyErr_SetString(PyExc_OSError, "message truncated");
                } else {
                    struct nlmsgerr *err = NLMSG_DATA(h);
                    errno = -err->error;
                    PyErr_SetString(PyExc_OSError, strerror(errno));
                }
                close(fd);
                return NULL;
                Py_RETURN_NONE;
            }

            struct inet_diag_msg *r = NLMSG_DATA(h);
            inet_ntop(AF_INET, &r->id.idiag_src, ipbuf, sizeof(ipbuf));
            PyList_Append(list, Py_BuildValue("si", ipbuf, ntohs(r->id.idiag_sport)));
            h = NLMSG_NEXT(h, len);
        }
    }
    out:
    free(buff);
    return list;
}


static PyMethodDef nl_methods[] = {
        {"bind", (PyCFunction) nlbind, METH_VARARGS | METH_KEYWORDS, "bind a netlink socket"},
        {"send", (PyCFunction) nlsend, METH_VARARGS | METH_KEYWORDS, "send a netlink message"},
        {"recv", (PyCFunction) nlrecv, METH_VARARGS,                 "receive netlink messages"},
        {}
};

PyMODINIT_FUNC initmymod(void) {
    (void) Py_InitModule("mymod", nl_methods);
}
