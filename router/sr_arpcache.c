#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <assert.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/*
The handle_arpreq() function is a function you should write, and it should
handle sending ARP requests if necessary:

function handle_arpreq(req):
    if difftime(now, req->sent) >= 1.0
        if req->times_sent >= 5:
            send icmp host unreachable to source addr of all pkts waiting
                on this request
            arpreq_destroy(req)
        else:
            send arp request
            req->sent = now
            req->times_sent++
*/

void send_type3_icmp (struct sr_instance *sr, int code, uint8_t * packet_buf, char * sending_iface) {
    sr_ethernet_hdr_t ethernet_header;
    memcpy(&ethernet_header, packet_buf, sizeof(sr_ethernet_hdr_t));
    // assert(ethernet_header.ether_type == htons(ethertype_ip));

    // packet = ethernet header + IP header + ICMP header
    // create a new ethernet header
    sr_ethernet_hdr_t ethernet_header_send;
    
    memcpy(&ethernet_header_send.ether_dhost, ethernet_header.ether_shost, ETHER_ADDR_LEN);
    memcpy(&ethernet_header_send.ether_shost, ethernet_header.ether_dhost, ETHER_ADDR_LEN);
    ethernet_header_send.ether_type = htons(ethertype_ip);
    
    // extract IP packet from ethernet frame
    sr_ip_hdr_t ip_header;
    memcpy(&ip_header, packet_buf + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

    // create a new IP header
    struct sr_if * sending_ip = sr_get_interface(sr, sending_iface);
    sr_ip_hdr_t ip_header_send;
    ip_header_send.ip_v = 4;
    ip_header_send.ip_hl = 5;
    ip_header_send.ip_ttl = INIT_TTL;
    ip_header_send.ip_p = ip_protocol_icmp;
    ip_header_send.ip_src = sending_ip->ip;  // ??????
    ip_header_send.ip_dst = ip_header.ip_src;
    ip_header_send.ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ip_header_send.ip_sum = 0;
    ip_header_send.ip_sum = cksum(&ip_header_send, sizeof(sr_ip_hdr_t));

    sr_icmp_t3_hdr_t icmp_header_send;
    icmp_header_send.icmp_type = 3;
    icmp_header_send.icmp_code = code;
    icmp_header_send.icmp_sum  = 0;
    // copy IP header and datagram into data of ICMP packet
    memcpy(icmp_header_send.data, packet_buf + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
    // calculate checksum (no need to care about next_mtu)
    uint16_t checksum = cksum(&icmp_header_send, sizeof(sr_icmp_t3_hdr_t));
    icmp_header_send.icmp_sum = checksum;
    
    // copy the whole packet
    unsigned int buf_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t* buf = malloc(buf_len);

    // copy ethernet header, IP header, ICMP header into buffer
    memcpy(buf, &ethernet_header_send, sizeof(sr_ethernet_hdr_t));
    memcpy(buf + sizeof(sr_ethernet_hdr_t), &ip_header_send, sizeof(sr_ip_hdr_t));
    memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &icmp_header_send, sizeof(sr_icmp_t3_hdr_t));

    if (sr_send_packet(sr, buf, buf_len, sending_iface) == -1) {
        printf("error on sending back icmp message!\n");
    }
    free(buf);
}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request) {
    time_t now = time(NULL);
    if (difftime(now, request->sent) >= 1.0) {
        if (request->times_sent >= 5) {
            // send icmp host unreachable to source addr of all pkts waiting on this request
            struct sr_packet *waiting_packet = request->packets;
            while (waiting_packet) {
                send_type3_icmp(sr, 1, waiting_packet->buf, waiting_packet->iface);
                waiting_packet = waiting_packet->next;
            }
            sr_arpreq_destroy(&sr->cache, request);
        }
        
        else {
            uint8_t dest_mac[ETHER_ADDR_LEN] = {255,255,255,255,255,255}; // broadcast: ff-ff-ff-ff-ff-ff
            // find the name of an interface from which the ARP request is sent
            fprintf(stderr, "Request IP = ");
            print_addr_ip_int(ntohl(request->ip));
            struct sr_rt* matching_entry = longest_prefix_match(sr, ntohl(request->ip));
            // find the interface by name
            struct sr_if* sender_if = sr_get_interface(sr, matching_entry->interface);
            fprintf(stderr, "sender_if IP = ");
            print_addr_ip_int(ntohl(sender_if->ip));
            // send ARP request
            send_arp_packet(sr, matching_entry->interface, 
					sender_if->addr, dest_mac, arp_op_request, 
					sender_if->addr, sender_if->ip, dest_mac, request->ip);
// void send_arp_packet(struct sr_instance *sr, const char * iface, 
// 					uint8_t * shost, uint8_t * dhost, unsigned short ar_op, 
// 					unsigned char * sha, uint32_t sip, unsigned char * tha, uint32_t tip)
				
            request->sent = now;
            request->times_sent++;
        }
    }
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    // Psudocode:
    // for each request on sr->cache.requests:
    //     handle_arpreq(request)
    struct sr_arpreq *request = sr->cache.requests;
    if (!request) return;
    struct sr_arpreq *next_request = request->next;
    while (request) {
        handle_arpreq(sr, request);
        request = next_request;
        if (!request) break;
        next_request = request->next;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

