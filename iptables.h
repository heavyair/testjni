/*
 * iptables.h
 *
 *  Created on: Feb 20, 2015
 *      Author: root
 */

#ifndef IPTABLES_H_
#define IPTABLES_H_
#define IP4_FORWARD_SWITCH_FILE "/proc/sys/net/ipv4/ip_forward"
#define IP4_ICMP_REDIRECT_FILE "/proc/sys/net/ipv4/conf/all/send_redirects"



bool iptables_commands(const char * p_sCmd);
bool GetIpforward();
void EnableIpforward(bool p_bTrue);
void EnableRedirect(std::string p_sInterfaceName,bool p_bEnable);
void FileWrite(std::string sFilename,std::string sData);
#endif /* IPTABLES_H_ */
