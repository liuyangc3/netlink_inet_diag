/*
 * Python C API wrapper for inet_diag_v2.c, tested with kernel 3.10.0
 * author web<liuyangc33@gmail.com>
 *
 *
 * compile:
 *     py2.7
 *     yum install python-devel
 *     gcc inet_diag_v2_python_c_module.c -fPIC -I/usr/include/python2.7 -shared -o inet_diag_v2.so
 *
 *     py3.6
 *     yum install python36-devel
 *     gcc -pthread -Wno-unused-result -Wsign-compare -DNDEBUG -g -fwrapv -O3 -Wall -Wstrict-prototypes -fPIC -I/usr/local/include/python3.6m -c inet_diag_v2_python_c_module.c -o inet_diag_v2_python_c_module.o
 *     gcc -pthread -shared inet_diag_v2_python_c_module.o -o inet_diag_v2.so
 *
 * use in Python:
 * import os, socket
 * import inet_diag_v2
 * sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 4)
 * sock.bind((os.getpid(), 0))
 * fd = sock.fileno()
 * inet_diag_v2.send(fd, 1<<10)
 * result = inet_diag_v2.recv(fd)
 * print(result)
 */

#include <Python.h>

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>


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

/*
  default tcp states: LISTEN | CLOSE | TIME_WAIT | SYN_RECV
*/
static const int default_states = SS_ALL & ~((1 << SS_LISTEN) |
                                             (1 << SS_CLOSE) |
                                             (1 << SS_TIME_WAIT) |
                                             (1 << SS_SYN_RECV));

static PyObject *nlsend(PyObject *self, PyObject *args, PyObject *kwargs) {
    int fd;
    int states = default_states;
    static char *kwlist[] = {"fd", "states", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ii", kwlist, &fd, &states))
        return NULL;



    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 r;
    } req = {
            .nlh = {
                    .nlmsg_len   = sizeof(req),
                    .nlmsg_type  = SOCK_DIAG_BY_FAMILY,
                    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                    .nlmsg_seq   = 0,
            },

            .r = {
                    .sdiag_family = AF_INET,
                    .sdiag_protocol = IPPROTO_TCP,
                    .idiag_states = states,
                    .idiag_ext = 0 | (1 << (INET_DIAG_INFO - 1))

            },
    };


    struct iovec iov[4] = {
            [0] = {
                    .iov_base = &req.nlh,
                    .iov_len  = sizeof(req.nlh),
            },
            [1] = {
                    .iov_base = &req.r,
                    .iov_len  = sizeof(req.r),
            },
    };

    struct sockaddr_nl nladdr = {
            .nl_family = AF_NETLINK,
            .nl_pid    = 0,         /* kernel */
    };
    struct msghdr msg = {
            .msg_name    = &nladdr,
            .msg_namelen = sizeof(nladdr),
            .msg_iov     = iov,
            .msg_iovlen  = 2,
    };

    if (sendmsg(fd, &msg, 0) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject *nlrecv(PyObject *self, PyObject *args) {
    int fd, len;

    if (!PyArg_ParseTuple(args, "i", &fd))
        return NULL;

    struct inet_diag_msg *diag_msg;
    char ipbuf[48];
    uint8_t recv_buf[16384];

    PyObject *list;
    Py_Initialize();
    list = PyList_New(0);


    while (1) {
        if ((len = recv(fd, recv_buf, sizeof(recv_buf), 0)) < 0) {
            close(fd);
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }

        struct nlmsghdr *h = (struct nlmsghdr *) recv_buf;

        while (NLMSG_OK(h, len)) {
            if (h->nlmsg_type == NLMSG_DONE)
                return list;

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


            diag_msg = (struct inet_diag_msg *) NLMSG_DATA(h);

            if (diag_msg->idiag_family == AF_INET) { // ipv4
                inet_ntop(AF_INET, (struct in_addr *) &diag_msg->id.idiag_src, ipbuf, sizeof(ipbuf));

            }
            PyList_Append(list, Py_BuildValue("si", ipbuf, ntohs(diag_msg->id.idiag_sport)));
            h = NLMSG_NEXT(h, len);
        }
    }
}



static PyMethodDef nl_methods[] = {
        {"send", (PyCFunction) nlsend, METH_VARARGS | METH_KEYWORDS, "send a netlink message"},
        {"recv", (PyCFunction) nlrecv, METH_VARARGS,                 "receive netlink messages"},
        {NULL, NULL, 0, NULL}        /* Sentinel */
};


// python2+
PyMODINIT_FUNC initmymod(void) {
    (void) Py_InitModule("mymod", nl_methods);
}

// python3+
static struct PyModuleDef inet_diag_v2 =
{
    PyModuleDef_HEAD_INIT,
    "inet_diag_v2", /* name of module */
    "",          /* module documentation, may be NULL */
    -1,          /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
    nl_methods
};

PyMODINIT_FUNC PyInit_inet_diag_v2(void) {
    return PyModule_Create(&inet_diag_v2);
}
