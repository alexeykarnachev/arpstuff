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
