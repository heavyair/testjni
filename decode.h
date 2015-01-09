/*
 * decode.h
 *
 *  Created on: Jun 15, 2014
 *      Author: root
 */

#ifndef DECODE_H_
#define DECODE_H_

#include "stdint.h"

/*  D E F I N E S  ************************************************************/
#define ETHERNET_MTU                  1500
#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_REVARP          0x8035
#define ETHERNET_TYPE_EAPOL           0x888e
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_IPX             0x8137
#define ETHERNET_TYPE_PPPoE_DISC      0x8863 /* discovery stage */
#define ETHERNET_TYPE_PPPoE_SESS      0x8864 /* session stage */
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_LOOP            0x9000



#define ETHERNET_HEADER_LEN             14
#define ETHERNET_MAX_LEN_ENCAP          1518    /* 802.3 (+LLC) or ether II ? */
#define PPPOE_HEADER_LEN                20    /* ETHERNET_HEADER_LEN + 6 */
#define MINIMAL_TOKENRING_HEADER_LEN    22
#define MINIMAL_IEEE80212_HEADER_LEN    10    /* Ack frames and others */
#define IEEE802_11_DATA_HDR_LEN         24    /* Header for data packets */
#define TR_HLEN                         MINIMAL_TOKENRING_HEADER_LEN
#define TOKENRING_LLC_LEN                8
#define SLIP_HEADER_LEN                 16

#define	ICMP_PROTOCOL	1
#define IGMP_PROTOCOL	2
#define TCP_PROTOCOL	6
#define	UDP_PROTOCOL	17


/*
 * Ethernet header
 */

typedef struct _EtherHdr
{
    u_int8_t ether_dst[6];
    u_int8_t ether_src[6];
    u_int16_t ether_type;

}         EtherHdr;


typedef struct _ARPHdr
{
    u_int16_t ar_hrd;       /* format of hardware address   */
    u_int16_t ar_pro;       /* format of protocol address   */
    u_int8_t ar_hln;        /* length of hardware address   */
    u_int8_t ar_pln;        /* length of protocol address   */
    u_int16_t ar_op;        /* ARP opcode (command)         */
}       ARPHdr;



typedef struct _EtherARP
{
    ARPHdr ea_hdr;      /* fixed-size header */
    u_int8_t arp_sha[6];    /* sender hardware address */
    u_int8_t arp_spa[4];    /* sender protocol address */
    u_int8_t arp_tha[6];    /* target hardware address */
    u_int8_t arp_tpa[4];    /* target protocol address */
}         EtherARP;

typedef struct _IPHdr
{
    u_int8_t ip_verhl;      /* version & header length */
    u_int8_t ip_tos;        /* type of service */
    u_int16_t ip_len;       /* datagram length */
    u_int16_t ip_id;        /* identification  */
    u_int16_t ip_off;       /* fragment offset */
    u_int8_t ip_ttl;        /* time to live field */
    u_int8_t ip_proto;      /* datagram protocol */
    u_int16_t ip_csum;      /* checksum */
    struct in_addr ip_src;  /* source IP */
    struct in_addr ip_dst;  /* dest IP */
}      IPHdr;


typedef struct _UDPHdr
{
    u_int16_t uh_sport;
    u_int16_t uh_dport;
    u_int16_t uh_len;
    u_int16_t uh_chk;

}       UDPHdr;


typedef struct _ICMPHdr
{
    u_int8_t type;
    u_int8_t code;
    u_int16_t csum;
    union
    {
        u_int8_t pptr;

        struct in_addr gwaddr;

        struct idseq
        {
            u_int16_t id;
            u_int16_t seq;
        } idseq;

        int sih_void;

        struct pmtu
        {
            u_int16_t ipm_void;
            u_int16_t nextmtu;
        } pmtu;

        struct rtradv
        {
            u_int8_t num_addrs;
            u_int8_t wpa;
            u_int16_t lifetime;
        } rtradv;
    } icmp_hun;

#define s_icmp_pptr       icmp_hun.pptr
#define s_icmp_gwaddr     icmp_hun.gwaddr
#define s_icmp_id         icmp_hun.idseq.id
#define s_icmp_seq        icmp_hun.idseq.seq
#define s_icmp_void       icmp_hun.sih_void
#define s_icmp_pmvoid     icmp_hun.pmtu.ipm_void
#define s_icmp_nextmtu    icmp_hun.pmtu.nextmtu
#define s_icmp_num_addrs  icmp_hun.rtradv.num_addrs
#define s_icmp_wpa        icmp_hun.rtradv.wpa
#define s_icmp_lifetime   icmp_hun.rtradv.lifetime

    union
    {
        /* timestamp */
        struct ts
        {
            u_int32_t otime;
            u_int32_t rtime;
            u_int32_t ttime;
        } ts;

        /* IP header for unreach */
        struct ih_ip
        {
            IPHdr *ip;
            /* options and then 64 bits of data */
        } ip;

        struct ra_addr
        {
            u_int32_t addr;
            u_int32_t preference;
        } radv;

        u_int32_t mask;

        char    data[1];

    } icmp_dun;
#define s_icmp_otime      icmp_dun.ts.otime
#define s_icmp_rtime      icmp_dun.ts.rtime
#define s_icmp_ttime      icmp_dun.ts.ttime
#define s_icmp_ip         icmp_dun.ih_ip
#define s_icmp_radv       icmp_dun.radv
#define s_icmp_mask       icmp_dun.mask
#define s_icmp_data       icmp_dun.data

}        ICMPHdr;




#endif /* DECODE_H_ */
