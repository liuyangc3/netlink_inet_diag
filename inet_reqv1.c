/*
 *	inet_diag_req version 1 test on kernel 2.6.32
 *	
 *	
 */


#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    int fd;
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG);

    // bind
    struct sockaddr_nl bind_nladdr = {
            .nl_family = AF_NETLINK,
            .nl_pid    = getpid(),
    };

    if (bind(fd, (struct sockaddr *) &bind_nladdr, sizeof(bind_nladdr)) < 0) {
        perror("can't bind socket\n");
        return -1;
    }


    // netlink request
    struct sockaddr_nl nladdr = {
            .nl_family = AF_NETLINK,
            .nl_pid    = 0,         /* kernel */
    };

    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req r;
    } req = {
            .nlh = {
                    // NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req)))
                    .nlmsg_len   = sizeof(req),
                    .nlmsg_type  = TCPDIAG_GETSOCK,
                    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                    .nlmsg_seq   = 1,
            },
            .r = {
                    .idiag_family = AF_INET,
                    .idiag_states = (1 << 10), // TCP_LISTEN
                    .id = {
                            .idiag_cookie[0] = INET_DIAG_NOCOOKIE,
                            .idiag_cookie[1] = INET_DIAG_NOCOOKIE,
                    },
            },
    };

    struct iovec iov_s[1] = {
            [0] = {
                    .iov_base = &req,
                    .iov_len  = sizeof(req),
            },
    };

    struct msghdr msg_s = {
            .msg_name    = &nladdr,
            .msg_namelen = sizeof(nladdr),
            .msg_iov     = iov_s,
            .msg_iovlen  = 1,
    };


    // send netlink request
    if (sendmsg(fd, &msg_s, 0) < 0) {
        perror("socket send error\n");
        return -1;
    }

    // receive netlink request
    int len;
    char buff[16384];
    char ip[48];

    struct iovec iov_r[1] = {
            [0] = {
                    .iov_base = buff,
                    .iov_len  = sizeof(buff),
            },
    };

    struct msghdr msg_r = {
            .msg_name    = &nladdr,
            .msg_namelen = sizeof(nladdr),
            .msg_iov     = iov_r,
            .msg_iovlen  = 1,
    };


    while (1) {
        if ((len = recvmsg(fd, &msg_r, 0)) < 0) {
            close(fd);
            fprintf(stderr, "recv error\n");
            return -1;
        }

        struct nlmsghdr *h = (struct nlmsghdr *) buff;

        while (NLMSG_OK(h, len)) {

            if (h->nlmsg_type == NLMSG_DONE) {
                close(fd);
                return 0;
            }

            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                    fprintf(stderr, "message truncated");
                    close(fd);
                } else {
                    struct nlmsgerr *err = NLMSG_DATA(h);
                    errno = -err->error;
                    fprintf(stderr, "nlmsg error %s\n", strerror(errno));
                    close(fd);
                    return -1;
                }
            }

            // parse msg data
            struct inet_diag_msg *r = NLMSG_DATA(h);
            printf("%s:%d\n",
                   inet_ntop(r->idiag_family, &r->id.idiag_src, ip, sizeof(ip)),
                   ntohs(r->id.idiag_sport));
            h = NLMSG_NEXT(h, len);
        }
    }
}
