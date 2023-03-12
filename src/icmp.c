#include "core.h"

icmp init_icmp(int seq) {
    icmp icmp_ = {0};
    icmp_.icmp_type = ICMP_ECHO;
    icmp_.icmp_code = 0;
    icmp_.icmp_id = getpid();
    icmp_.icmp_seq = htons(seq);
    return icmp_;
}

void send_icmp_request(
    int icmp_sock, int seq, u32 target_addr_hl, u8 target_port_hs
) {
    sockaddr_in addr = get_af_inet_sockaddr_in(
        target_addr_hl, target_port_hs
    );

    icmp icmp_ = init_icmp(seq);

    if (sendto(
            icmp_sock,
            &icmp_,
            sizeof(icmp),
            0,
            (sockaddr*)&addr,
            sizeof(addr)
        )
        == -1) {
        perror("ERROR: send_icmp_request, failed to sendto an icmp "
               "request via the icmp_sock");
        close(icmp_sock);
        exit(1);
    }
}

int receive_icmp_reply(int icmp_sock, icmp* rep, int timeout_sec) {
    fd_set socks;
    FD_ZERO(&socks);
    FD_SET(icmp_sock, &socks);
    timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;

    if (select(icmp_sock + 1, &socks, NULL, NULL, &timeout) <= 0) {
        fprintf(
            stderr,
            "WARNING: receive_icmp_rely, failed to select a socket\n"
        );
        return 0;
    }

    u8 buffer[128];
    if (recv(icmp_sock, buffer, sizeof(buffer), 0) < 0) {
        fprintf(
            stderr,
            "WARNING: receive_icmp_reply, failed to recv a reply from the "
            "icmp_sock"
        );
        return 0;
    }

    iphdr* ip = (iphdr*)buffer;
    memcpy(rep, buffer + (ip->ihl * 4), sizeof(icmp));
    if (rep->icmp_type == ICMP_ECHOREPLY) {
        return 1;
    } else {
        fprintf(
            stderr,
            "WARNING: receive_icmp_reply, the reply is received, but its "
            "type is not equal to ICMP_ECHOREPLY\n"
        );
        return 0;
    }
}
