#include <stdlib.h>
#include "checksum.h"


static int do_checksum_math(uint16_t *, int);


/**
 * Returns -1 on error and 0 on success, 1 on warn
 */
int
do_checksum(uint8_t *data, int proto, int len) {
    ipv4_hdr_t *ipv4;
    ipv6_hdr_t *ipv6;
    tcp_hdr_t *tcp;
    udp_hdr_t *udp;
    icmpv4_hdr_t *icmp;
    icmpv6_hdr_t *icmp6;
    int ip_hl;
    int sum;

    sum = 0;
    ipv4 = NULL;
    ipv6 = NULL;

    if (len <= 0) {
        return -1;
    }

    ipv4 = (ipv4_hdr_t *)data;
    if (ipv4->ip_v == 6) {
        return -1;
    } else {
        ip_hl = ipv4->ip_hl << 2;
    }

    switch (proto) {

        case IPPROTO_TCP:
            tcp = (tcp_hdr_t *)(data + ip_hl);
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
            tcp->th_sum = tcp->th_off << 2;
            return (TCPEDIT_OK);
#endif
            tcp->th_sum = 0;

            /* Note, we do both src & dst IP's at the same time, that's why the
             * length is 2x a single IP
             */
            if (ipv6 != NULL) {
                sum = do_checksum_math((uint16_t *)&ipv6->ip_src, 32);
            } else {
                sum = do_checksum_math((uint16_t *)&ipv4->ip_src, 8);
            }
            sum += ntohs(IPPROTO_TCP + len);
            sum += do_checksum_math((uint16_t *)tcp, len);
            tcp->th_sum = CHECKSUM_CARRY(sum);
            break;

        case IPPROTO_UDP:
            udp = (udp_hdr_t *)(data + ip_hl);
            /* No need to recalculate UDP checksums if already 0 */
            if (udp->uh_sum == 0)
                break;
            udp->uh_sum = 0;
            if (ipv6 != NULL) {
                sum = do_checksum_math((uint16_t *)&ipv6->ip_src, 32);
            } else {
                sum = do_checksum_math((uint16_t *)&ipv4->ip_src, 8);
            }
            sum += ntohs(IPPROTO_UDP + len);
            sum += do_checksum_math((uint16_t *)udp, len);
            udp->uh_sum = CHECKSUM_CARRY(sum);
            break;

        case IPPROTO_ICMP:
            icmp = (icmpv4_hdr_t *)(data + ip_hl);
            icmp->icmp_sum = 0;
            if (ipv6 != NULL) {
                sum = do_checksum_math((uint16_t *)&ipv6->ip_src, 32);
                icmp->icmp_sum = CHECKSUM_CARRY(sum);
            }
            sum += do_checksum_math((uint16_t *)icmp, len);
            icmp->icmp_sum = CHECKSUM_CARRY(sum);
            break;

        case IPPROTO_ICMP6:
            icmp6 = (icmpv6_hdr_t *)(data + ip_hl);
            icmp6->icmp_sum = 0;
            if (ipv6 != NULL) {
                sum = do_checksum_math((u_int16_t *)&ipv6->ip_src, 32);
            }
            sum += ntohs(IPPROTO_ICMP6 + len);
            sum += do_checksum_math((u_int16_t *)icmp6, len);
            icmp6->icmp_sum = CHECKSUM_CARRY(sum);
            break;


        case IPPROTO_IP:
            ipv4->ip_sum = 0;
            sum = do_checksum_math((uint16_t *)data, ip_hl);
            ipv4->ip_sum = CHECKSUM_CARRY(sum);
            break;

        case IPPROTO_IGMP:
        case IPPROTO_GRE:
        case IPPROTO_OSPF:
        case IPPROTO_OSPF_LSA:
        case IPPROTO_VRRP:
        case TCPR_PROTO_CDP:
        case TCPR_PROTO_ISL:
        default:
            //tcpedit_setwarn(tcpedit, "Unsupported protocol for checksum: 0x%x", proto);
            return 1;
    }

    return 0;
}

/**
 * code to do a ones-compliment checksum
 */
static int
do_checksum_math(uint16_t *data, int len)
{
    int sum = 0;
    union {
        uint16_t s;
        uint8_t b[2];
    } pad;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    if (len == 1) {
        pad.b[0] = *(uint8_t *)data;
        pad.b[1] = 0;
        sum += pad.s;
    }

    return (sum);
}
