/*
 * use inet_diag_req_v2 test on kernel 3.3
 * author web <liuyangc3@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <pwd.h>


#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING
};

int send_diag_msg(int sockfd) {

    struct msghdr msg;
    struct sockaddr_nl sa;
    struct nlmsghdr nlh;
    struct inet_diag_req_v2 conn_req;

    memset(&msg, 0, sizeof(msg));
    memset(&sa, 0, sizeof(sa));
    memset(&nlh, 0, sizeof(nlh));
    memset(&conn_req, 0, sizeof(conn_req));

    // message receiver
    sa.nl_family = AF_NETLINK;

    conn_req.sdiag_family = AF_INET;
    conn_req.sdiag_protocol = IPPROTO_TCP;
    conn_req.idiag_states = TCP_LISTEN;
    conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));

    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
    nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;


    struct iovec iov[4];
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    iov[0].iov_base = (void *) &nlh;
    iov[0].iov_len = sizeof(nlh);
    iov[1].iov_base = (void *) &conn_req;
    iov[1].iov_len = sizeof(conn_req);

    msg.msg_name = (void *) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    int retval = 0;
    retval = (int) sendmsg(sockfd, &msg, 0);
    return retval;
}


void parse_diag_msg(struct inet_diag_msg *diag_msg, int rtalen) {
    char local_addr_buf[INET6_ADDRSTRLEN];
    char remote_addr_buf[INET6_ADDRSTRLEN];
    memset(&local_addr_buf, 0, sizeof(local_addr_buf));
    memset(&remote_addr_buf, 0, sizeof(remote_addr_buf));

    struct passwd *user_info = NULL;
    user_info = getpwuid(diag_msg->idiag_uid);

    int indoe = diag_msg->idiag_inode;

    if (diag_msg->idiag_family == AF_INET) {
        // ipv4
        inet_ntop(AF_INET, (struct in_addr *) &diag_msg->id.idiag_src, local_addr_buf, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (struct in_addr *) &diag_msg->id.idiag_dst, remote_addr_buf, INET_ADDRSTRLEN);
    } else if (diag_msg->idiag_family == AF_INET6) {
        // ipv6
        inet_ntop(AF_INET6, (struct in_addr *) &diag_msg->id.idiag_src, local_addr_buf, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (struct in_addr *) &diag_msg->id.idiag_dst, remote_addr_buf, INET6_ADDRSTRLEN);
    } else {
        fprintf(stderr, "unknown protocol");
        return;
    }

    // check addr buf parse
    if (local_addr_buf[0] == 0 || remote_addr_buf[0] == 0) {
        fprintf(stderr, "addr parse failed");
        return;
    } else {
        fprintf(stdout, "%s,%s:%d,%d\n",
                user_info == NULL ? "Not found" : user_info->pw_name,
                local_addr_buf, ntohs(diag_msg->id.idiag_sport), indoe);
    }
}


int main() {
    //create netlink socket
    int nl_sock = 0;
    if ((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1) {
        perror("socket create failure");
        return EXIT_FAILURE;
    };

    struct inet_diag_msg *diag_msg;
    struct nlmsghdr *nlh;
    uint8_t recv_buf[SOCKET_BUFFER_SIZE];


    if (send_diag_msg(nl_sock) < 0) {
        perror("send msg:");
        return EXIT_FAILURE;
    };

    int bytes = 0, rtalen = 0;
    while (1) {
        bytes = (int) recv(nl_sock, recv_buf, sizeof(recv_buf), 0);
        nlh = (struct nlmsghdr *) recv_buf;

        while (NLMSG_OK(nlh, bytes)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                return EXIT_SUCCESS;
            }

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                fprintf(stderr, "Error in netlink message\n");
                return EXIT_FAILURE;
            }

            diag_msg = (struct inet_diag_msg *) NLMSG_DATA(nlh);
            rtalen = (int) (nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg)));
            parse_diag_msg(diag_msg, rtalen);

            nlh = NLMSG_NEXT(nlh, bytes);
        }
    }
    return EXIT_SUCCESS;
}
