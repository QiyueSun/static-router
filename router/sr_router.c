/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

void print_arp_entries(struct sr_instance *sr) {
  for (int i = 0; i < SR_ARPCACHE_SZ; i++) {
    if (!(sr->cache.entries[i].valid))
      break;
    else {
      // fprintf(stderr, )
      fprintf(stderr, "entry %d:\n", i);
      fprintf(stderr, "\tmac: ");
      print_addr_eth(sr->cache.entries[i].mac);
      fprintf(stderr, "\tip: ");
      print_addr_ip_int(sr->cache.entries[i].ip);
    }
  }
}

/*
	Given an IP address, perform longest prefix match.
	Return an entry in the routing table.
*/
struct sr_rt* longest_prefix_match(struct sr_instance *sr, uint32_t ip) {
	struct sr_rt* routing_table = sr->routing_table;
	uint32_t longest_mask = 0;
	char send_if_name[sr_IFACE_NAMELEN];
	struct sr_rt* match_entry = 0;
	while (routing_table) {
		uint32_t mask = routing_table->mask.s_addr;
		uint32_t target_addr = routing_table->dest.s_addr & mask;
		// print_addr_ip_int(ntohl(mask));
		// print_addr_ip_int(ntohl(target_addr));
		// print_addr_ip_int((ip & mask));
		if ((ip & mask) == ntohl(target_addr)) {
			// longest prefix has largest value of mask
			if (mask >= longest_mask) {
				match_entry = routing_table;
				longest_mask = mask;
			}
		}
		routing_table = routing_table->next;
	}
	return match_entry;
}

void send_arp_packet(struct sr_instance *sr, const char * iface, 
					uint8_t * shost, uint8_t * dhost,
					unsigned short ar_op, // in host byte
					unsigned char * sha,
					uint32_t sip, // in network byte
					unsigned char * tha,
					uint32_t tip // in network byte
					) {
						
	sr_ethernet_hdr_t ethernet_header_send;
	memcpy(ethernet_header_send.ether_dhost, dhost, ETHER_ADDR_LEN);
	memcpy(ethernet_header_send.ether_shost, shost, ETHER_ADDR_LEN);
	ethernet_header_send.ether_type = htons(ethertype_arp);

	sr_arp_hdr_t arp_header_send;
	arp_header_send.ar_hrd = htons(arp_hrd_ethernet);
	arp_header_send.ar_pro = htons(ethertype_ip);
	arp_header_send.ar_op = htons(ar_op);
	arp_header_send.ar_hln = 6;
	arp_header_send.ar_pln = 4;
	
	memcpy(arp_header_send.ar_sha, sha, ETHER_ADDR_LEN);
	arp_header_send.ar_sip = sip;

	memcpy(arp_header_send.ar_tha, tha, ETHER_ADDR_LEN);
	arp_header_send.ar_tip = tip;

    unsigned int buf_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t* buf = malloc(buf_len);
	memcpy(buf, &ethernet_header_send, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), &arp_header_send, sizeof(sr_arp_hdr_t));

	if (sr_send_packet(sr, buf, buf_len, iface) == -1) {
		printf("error on sending back icmp message!\n");
	}
	fprintf(stderr, "send arp packet from %s\n", iface);
	free(buf);
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/



// handle additional case: send icmp when ttl, after decremented, is 0

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d at %s\n", len, interface);

	// extract ethernet header
	sr_ethernet_hdr_t ethernet_header;
	memcpy(&ethernet_header, packet, sizeof(sr_ethernet_hdr_t));
	// print_hdr_eth(packet);
	// packet is ip type
	if (ntohs(ethernet_header.ether_type) == ethertype_ip) {
		// print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
		sr_ip_hdr_t ip_header;
		memcpy(&ip_header, packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
		// print_hdr_ip(&ip_header);
		
		// check that the packet is valid
		uint16_t old_checksum = ip_header.ip_sum;
		ip_header.ip_sum = 0;
		if (old_checksum == cksum(&ip_header, sizeof(sr_ip_hdr_t))) {
			uint32_t dest_ip = ntohl(ip_header.ip_dst);
			int forwarding = 0; // 0 - forwarding; 1 - for me
			// check if IP packet is sent to rounter's IP address
			struct sr_if* if_list = sr->if_list;
			while (if_list) {
				if (ntohl(if_list->ip) == dest_ip) {
					forwarding = 1;
					break;
				}
				if_list = if_list->next;
			}
			fprintf(stderr, "forwarding = %d\n", forwarding);
			
			if (forwarding == 1) {
				/*
					If the packet is an ICMP echo request and its checksum is valid,
					send an ICMP echo reply to the sending host.
				*/
				if (ip_header.ip_p == ip_protocol_icmp) {
					sr_icmp_hdr_t icmp_header;
					memcpy(&icmp_header, packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_hdr_t));
					print_hdr_icmp(&icmp_header);
					uint16_t old_icmp_sum = icmp_header.icmp_sum;
					icmp_header.icmp_sum = 0;
					unsigned int icmp_buf_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
					uint8_t* icmp_buf = malloc(icmp_buf_len);
					memcpy(icmp_buf, packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_buf_len);
					memcpy(icmp_buf, &icmp_header, sizeof(sr_icmp_hdr_t));
					fprintf(stderr, "icmp old checksum = %d\n",old_icmp_sum);
					fprintf(stderr, "icmp new checksum = %d\n", cksum(icmp_buf, icmp_buf_len));
					// packet is an ICMP echo request and checksum (compute on header + data) is valid
					if (icmp_header.icmp_type == 8 &&
						old_icmp_sum == cksum(icmp_buf, icmp_buf_len)) {   // ?????

						// create a new ethernet header
						sr_ethernet_hdr_t ethernet_header_send;
						memcpy(&ethernet_header_send.ether_dhost, ethernet_header.ether_shost, ETHER_ADDR_LEN);
						memcpy(&ethernet_header_send.ether_shost, ethernet_header.ether_dhost, ETHER_ADDR_LEN);
						ethernet_header_send.ether_type = htons(ethertype_ip);

						// create a new IP header
						sr_ip_hdr_t ip_header_send;
						ip_header_send.ip_v = 4;
						ip_header_send.ip_hl = 5;
						ip_header_send.ip_ttl = INIT_TTL;
						ip_header_send.ip_p = ip_protocol_icmp;
						ip_header_send.ip_src = ip_header.ip_dst;
						ip_header_send.ip_dst = ip_header.ip_src;  // ?????????
						ip_header_send.ip_len = ip_header.ip_len;
						ip_header_send.ip_sum = 0;
						ip_header_send.ip_sum = cksum(&ip_header_send, sizeof(sr_ip_hdr_t));
						print_hdr_ip(&ip_header_send);

						// create a new ICMP header
						sr_icmp_hdr_t icmp_header_send;
						icmp_header_send.icmp_type = 0;
						icmp_header_send.icmp_code = 0;
						icmp_header_send.icmp_sum = 0;
						memcpy(icmp_buf, &icmp_header_send, sizeof(sr_icmp_hdr_t));
						icmp_header_send.icmp_sum = cksum(icmp_buf, icmp_buf_len);
						memcpy(icmp_buf, &icmp_header_send, sizeof(sr_icmp_hdr_t));
						print_hdr_icmp(icmp_buf);

						// original packet: ethernet | ip | icmp | data?
						// reply packet   : ethernet | ip | icmp | data?
						// copy whole packet into buffer
						uint8_t* buf = malloc(len);
						memcpy(buf, packet, len);

						// copy ethernet header, IP header, ICMP header into buffer
						memcpy(buf, &ethernet_header_send, sizeof(sr_ethernet_hdr_t));
						memcpy(buf + sizeof(sr_ethernet_hdr_t), &ip_header_send, sizeof(sr_ip_hdr_t));
						memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_buf, icmp_buf_len);
						// print_hdrs(buf, len);
						if (sr_send_packet(sr, buf, len, interface) == -1) {
							printf("error on sending back icmp message!\n");
						}
						fprintf(stderr, "send icmp echo reply from %s\n", interface);
						free(buf);
					}
					free(icmp_buf);
				}
				
				// If the packet contains a TCP or UDP payload,
				// send an ICMP port unreachable to the sending host.
				else if (ip_header.ip_p == ip_protocol_tcp || ip_header.ip_p == ip_protocol_udp) {
					fprintf(stderr, "tcp or udp\n");
					send_type3_icmp (sr, 3, packet, interface);
				}
				// Otherwise, ignore the packet.
			}

			// forward the packet
			else {
				// Decrement the TTL by 1, and recompute the packet checksum over the modified header.
				ip_header.ip_ttl--;
				if (ip_header.ip_ttl == 0) {
					sr_ethernet_hdr_t ethernet_header_send;
					memcpy(&ethernet_header_send.ether_dhost, ethernet_header.ether_shost, ETHER_ADDR_LEN);
					memcpy(&ethernet_header_send.ether_shost, ethernet_header.ether_dhost, ETHER_ADDR_LEN);
					ethernet_header_send.ether_type = htons(ethertype_ip);

					struct sr_if* send_if = sr_get_interface(sr, interface);
					
					sr_ip_hdr_t ip_header_send;
                    ip_header_send.ip_v = 4;
                    ip_header_send.ip_hl = 5;
                    ip_header_send.ip_ttl = INIT_TTL;
                    ip_header_send.ip_p = ip_protocol_icmp;
                    ip_header_send.ip_src = send_if->ip; // ??
                    ip_header_send.ip_dst = ip_header.ip_src;
					ip_header_send.ip_len = htons(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));
                    ip_header_send.ip_sum = 0;
					ip_header_send.ip_sum = cksum(&ip_header_send, sizeof(sr_ip_hdr_t));
					
					sr_icmp_t3_hdr_t icmp_header_send;
					icmp_header_send.icmp_type = 11;
					icmp_header_send.icmp_code = 0;
					icmp_header_send.icmp_sum  = 0;
					memcpy(icmp_header_send.data, packet + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
                    icmp_header_send.icmp_sum = cksum(&icmp_header_send, sizeof(sr_icmp_t3_hdr_t));
					
					unsigned int buf_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
					uint8_t* buf = malloc(buf_len);
					// copy ethernet header, IP header, ICMP header into buffer
					memcpy(buf, &ethernet_header_send, sizeof(sr_ethernet_hdr_t));
					memcpy(buf + sizeof(sr_ethernet_hdr_t), &ip_header_send, sizeof(sr_ip_hdr_t));
					memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &icmp_header_send, sizeof(sr_icmp_t3_hdr_t));
					if (sr_send_packet(sr, buf, buf_len, interface) == -1) {
						printf("error on sending back icmp message!\n");
					}
					fprintf(stderr, "send icmp 11 from %s\n", interface);
					free(buf);
					return;
				}

				ip_header.ip_sum = 0;
				ip_header.ip_sum = cksum(&ip_header, sizeof(sr_ip_hdr_t));
				// fprintf(stderr, "before longest_prefix_match\n");
				// longest prefix match with the destination IP address
				struct sr_rt* matching_entry = longest_prefix_match(sr, ntohl(ip_header.ip_dst));
				// fprintf(stderr, "after longest_prefix_match\n");
				// if no matching LPM, send ICMP net unreachable
				if (!matching_entry) {
					send_type3_icmp(sr, 0, packet, interface);
					return;
				}

				in_addr_t next_hop_ip = matching_entry->gw.s_addr;
				struct sr_if* send_if = sr_get_interface(sr, matching_entry->interface);
				fprintf(stderr, "next_hop_ip: ");
				print_addr_ip_int(next_hop_ip);
				// Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP
				struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
				if (entry) {
					// If next-hop MAC found, send it
					sr_ethernet_hdr_t ethernet_header_send;
					memcpy(ethernet_header_send.ether_dhost, entry->mac, ETHER_ADDR_LEN);
					memcpy(ethernet_header_send.ether_shost, send_if->addr, ETHER_ADDR_LEN);
					ethernet_header_send.ether_type = htons(ethertype_ip);
					// print_hdr_eth(&ethernet_header_send);
					uint8_t* buf = malloc(len);
					memcpy(buf, packet, len);

					// change the ethernet header and IP header accordingly
					memcpy(buf, &ethernet_header_send, sizeof(sr_ethernet_hdr_t));
					// print_hdr_eth(buf);
					memcpy(buf + sizeof(sr_ethernet_hdr_t), &ip_header, sizeof(sr_ip_hdr_t));
					print_hdrs(buf, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					// forward this packet
					if (sr_send_packet(sr, buf, len, matching_entry->interface) == -1) {
						printf("error on sending back icmp message!\n");
					}
					fprintf(stderr, "forward packet from %s\n", matching_entry->interface);
					free(buf);
				}
				else {
					uint8_t* buf = malloc(len);
					memcpy(buf, packet, len);
					fprintf(stderr, "add waiting packet of length %d\n", len);
					// print_hdrs(buf, len);
					// add the packet to the queue of packets waiting on this ARP request
					struct sr_arpreq * arp_request = sr_arpcache_queuereq(&sr->cache, next_hop_ip, buf, len, interface);
					// send ARP request for next-hop IP
					handle_arpreq(sr, arp_request);
					/* buf now lives in queue and should not be freed here */
					free(buf);
				}
			}
		}
	}

	// packet is arp type
	else if (ntohs(ethernet_header.ether_type) == ethertype_arp){
		// extract arp packet from ethernet frame
		sr_arp_hdr_t arp_header;
        memcpy(&arp_header, packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_arp_hdr_t));
		struct sr_if* iface = sr_get_interface(sr, interface);
		print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
		// packet is arp request
		if (ntohs(arp_header.ar_op) == arp_op_request){
			unsigned char * target_mac_addr = 0;
			
			// loop through the current interface
			struct sr_if* if_walker = sr->if_list;
			while (if_walker) {
				print_addr_ip_int(ntohs(if_walker->ip));
				if (ntohs(if_walker->ip) == ntohs(arp_header.ar_tip)) {
					target_mac_addr = (unsigned char *)malloc(ETHER_ADDR_LEN);
					memcpy(target_mac_addr, if_walker->addr, ETHER_ADDR_LEN);
					break;
				}
				if_walker = if_walker->next;
			}
			print_addr_eth(target_mac_addr);
			
			// if we get a valid mac address, we send arp_reply
			if (target_mac_addr) {
				send_arp_packet(sr, interface, iface->addr, ethernet_header.ether_shost, 
					arp_op_reply, target_mac_addr, iface->ip, ethernet_header.ether_shost, arp_header.ar_sip);
				free(target_mac_addr);
			}
		}
		// packet is arp reply 
		else if (ntohs(arp_header.ar_op) == arp_op_reply) {
			struct sr_arpreq * pending_request = sr_arpcache_insert(&sr->cache, arp_header.ar_sha, arp_header.ar_sip);
			print_arp_entries(sr);
			// assert(pending_request);
			if (pending_request) {
				struct sr_packet * waiting_packet = pending_request->packets;
				while(waiting_packet) {
					sr_ethernet_hdr_t ethernet_header_send;
					memcpy(ethernet_header_send.ether_dhost, arp_header.ar_sha, ETHER_ADDR_LEN);
					memcpy(ethernet_header_send.ether_shost, iface->addr, ETHER_ADDR_LEN);
					ethernet_header_send.ether_type = htons(ethertype_ip);

					uint8_t* buf = malloc(waiting_packet->len);
					memcpy(buf, waiting_packet->buf, waiting_packet->len);
					// change the ethernet header and IP header accordingly
					memcpy(buf, &ethernet_header_send, sizeof(sr_ethernet_hdr_t));

					if (sr_send_packet(sr, buf, waiting_packet->len, interface) == -1) {
						printf("error on sending back icmp message!\n");
					}
					fprintf(stderr, "resolve waiting packet of length %d receiving from %s and send from %s\n", waiting_packet->len, waiting_packet->iface, interface);
					// print_hdrs(buf, waiting_packet->len);
					free(buf);
					waiting_packet = waiting_packet->next;
				}
				sr_arpreq_destroy(&sr->cache, pending_request);
			}
		}
	}

} /* end sr_ForwardPacket */
