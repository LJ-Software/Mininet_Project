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

void sr_init(struct sr_instance* sr)
{
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

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr = 
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr = 
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply); 
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr, 
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr = 
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request); 
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr, 
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or  
 * or generate an ARP request packet 
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
      /* packets waiting on this request                                   */
      struct sr_packet *pack = req->packets;
      unsigned int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
      uint8_t *icmp_pkt = (uint8_t *)malloc(icmp_len);
      if (NULL == icmp_pkt)
      {
        fprintf(stderr,"Failed to allocate space for ICMP message");
        return;
      }
      sr_ethernet_hdr_t *icmp_ethhdr = (sr_ethernet_hdr_t *)icmp_pkt;
      sr_ip_hdr_t *icmp_ip = (sr_ip_hdr_t *)(icmp_pkt + sizeof(sr_ethernet_hdr_t));
      sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(icmp_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      /* For each packet in req->packets */
      do
      {
        uint8_t *buf = pack->buf;
        uint16_t ethtype = ethertype(buf);
        if (ethtype == ethertype_ip)
        {
          sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
          /* Populate Ethernet header */
          memcpy(icmp_ethhdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(icmp_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
          icmp_ethhdr->ether_type = ehdr->ether_type;
          
          sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
          /* Populate IP header */
          icmp_ip->ip_tos = iphdr->ip_tos;
          icmp_ip->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
          icmp_ip->ip_id = iphdr->ip_id;
          icmp_ip->ip_off = 0x0000;
          icmp_ip->ip_ttl = 0xFF;
          icmp_ip->ip_p = 0x01;
          icmp_ip->ip_sum = 0x0000;
          icmp_ip->ip_src = out_iface->ip;
          icmp_ip->ip_dst = iphdr->ip_src;
          /* Calculate IP checksum */
          icmp_ip->ip_sum = cksum(icmp_ip, sizeof(sr_ip_hdr_t));
          
          /* Populate ICMP header */
          icmp_t3_hdr->icmp_type = 0x03;
          icmp_t3_hdr->icmp_code = 0x01;
          icmp_t3_hdr->icmp_sum = 0x0000;
          icmp_t3_hdr->unused = 0x0000;
          icmp_t3_hdr->next_mtu = 0x0000;
          memcpy(icmp_t3_hdr->data, iphdr, ICMP_DATA_SIZE);
          /* Calculate ICMP checksum */
          icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
          
          /* Send packet to source address */
	fprintf(stderr,"Attempting to send ICMP host unreachable to queued ARP requests\n");
		print_hdrs(icmp_pkt,icmp_len);
          sr_send_packet(sr, icmp_pkt, icmp_len, out_iface->name);
        }
        /* Prepare next packet */
        pack = pack->next;
      } while(pack);
      free(icmp_pkt);
      /*********************************************************************/

      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    { 
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);
       
      /* Update ARP request entry to indicate ARP request packet was sent */ 
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq -- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip, 
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, 
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }

    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */
	 struct sr_packet *req_list = req->packets;
	    
	 while(req_list){
	fprintf(stderr,"Attempting to send the queued arp request packet\n");
	print_hdrs(req_list->buf,req_list->len);
	
	sr_ethernet_hdr_t *send_pkt_eth = (sr_ethernet_hdr_t *)(req_list->buf);
	memcpy(send_pkt_eth->ether_shost,src_iface->addr,ETHER_ADDR_LEN);
	 sr_send_packet(sr,req_list->buf,req_list->len,req_list->iface);
	 req_list = req_list->next;
	 }
	    
	    
	/* struct sr_packet *packet_linkedlist = req->packets; 

	printf("ARP Packet: ");
	print_hdrs(pkt,len);

		while(packet_linkedlist != NULL){

			sr_ethernet_hdr_t *packet_linkedlist_ethernet = (sr_ethernet_hdr_t *)(packet_linkedlist->buf);
			sr_arp_hdr_t *packet_linkedlist_arp = (sr_arp_hdr_t *)(packet_linkedlist->buf + sizeof(sr_ethernet_hdr_t));
			
			
			memcpy(packet_linkedlist_ethernet->ether_shost, packet_linkedlist_arp->ar_tha, ETHER_ADDR_LEN * sizeof(uint8_t));
			memcpy(packet_linkedlist_ethernet->ether_dhost, packet_linkedlist_arp->ar_sha, ETHER_ADDR_LEN * sizeof(uint8_t));
			
			Sends packet to the linked list 
			sr_send_packet(sr,&(packet_linkedlist->buf),packet_linkedlist->len,packet_linkedlist->iface);

			After the packet is sent it is directed to the next one  
			packet_linkedlist = packet_linkedlist->next;
		}*/
      /*********************************************************************/

      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }    
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */

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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /*************************************************************************/
  /* TODO: Handle packets                                                  */
    
  /* Cast received ethernet packet into ethernet header format given by sr_protocol.h */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "Failed to parse ETHERNET header, insufficient length\n");
    return;
  }

  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet;
    
  /* Determine if packet is ARP or IP */
    switch(ethertype(packet)){
      /* If ARP: pass to sr_handlepacket_arp function */
      case 2054:
      sr_handlepacket_arp(sr,packet,len,sr_get_interface(sr,interface));
      break;
    
      /* If IP: */
      case 2048: ;
      sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        /* Check if IP packet length meets minimum */
      if (len < (minlength + sizeof(sr_ip_hdr_t))) {
      fprintf(stderr, "Failed to parse IP header, insufficient length\n");
      return;
      }
        /* Validate IP header */
            /* Validate checksum (sr_utils.c) */
		uint16_t orig_ip_sum = iphdr->ip_sum;
		iphdr->ip_sum = 0;
            uint16_t _checksum = cksum(iphdr,sizeof(sr_ip_hdr_t));
            if (_checksum != orig_ip_sum){
              fprintf(stderr, "IP header checksums do not match! Discarding packet.\n");
              break;
            }
        /* Check if this packet is destined to this router or not */
    int isDestinedForRouter = 0;

    struct sr_if* if_walker = 0;

    if_walker = sr->if_list;
    
    while(if_walker->next){
        if_walker = if_walker->next;
        if (iphdr->ip_dst == if_walker->ip){
          isDestinedForRouter = 1;
        }
    }

    /* if the packet IS destined for this router */
    if(isDestinedForRouter == 1){
      /* if the IP protocol is ICMP: respond */
      if(iphdr->ip_p == 1){
        sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        switch(icmphdr->icmp_type){
          case 8: ;
          /* Build packet to send */
              uint32_t send_pkt_len = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
              uint8_t *send_pkt = malloc(send_pkt_len);

              sr_ethernet_hdr_t *send_pkt_eth = (sr_ethernet_hdr_t *)send_pkt;
              sr_ip_hdr_t *send_pkt_ip = (sr_ip_hdr_t *)(send_pkt + sizeof(sr_ethernet_hdr_t));
              sr_icmp_hdr_t *send_pkt_icmp = (sr_icmp_hdr_t *)(send_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

              memcpy(send_pkt_eth->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
        	memcpy(send_pkt_eth->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
              send_pkt_eth->ether_type = htons(ethertype_ip);

              send_pkt_ip->ip_tos = iphdr->ip_tos;
              send_pkt_ip->ip_len = (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
              send_pkt_ip->ip_id = iphdr->ip_id;
              send_pkt_ip->ip_off = 0;
              send_pkt_ip->ip_ttl = 255;
              send_pkt_ip->ip_p = 1;
              send_pkt_ip->ip_sum = 0;
              uint32_t ip_new_src = iphdr->ip_src;;
          send_pkt_ip->ip_src = iphdr->ip_dst;
          send_pkt_ip->ip_dst = ip_new_src;
              
              send_pkt_ip->ip_sum = cksum(send_pkt_ip, sizeof(sr_ip_hdr_t));

              send_pkt_icmp->icmp_type = 0;
              send_pkt_icmp->icmp_code = 0;
              send_pkt_icmp->icmp_sum = cksum(send_pkt_icmp, sizeof(sr_icmp_hdr_t));

		fprintf(stderr,"Attempting to send the following ICMP Response packet\n");
		print_hdrs(send_pkt, send_pkt_len);
			
          sr_send_packet(sr, send_pkt, send_pkt_len, interface);
	free(send_pkt);
          break;
        }
        /* if the IP protocol is TCP (6) or UDP (17): respond with port unreachable */
      } else if (iphdr->ip_p == 6 || iphdr->ip_p == 17){
          uint32_t send_pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
          uint8_t *send_pkt = (uint8_t *)malloc(send_pkt_len);

          sr_ethernet_hdr_t *send_pkt_eth = (sr_ethernet_hdr_t *)send_pkt;
          sr_ip_hdr_t *send_pkt_ip = (sr_ip_hdr_t *)(send_pkt + sizeof(sr_ethernet_hdr_t));
          sr_icmp_hdr_t *send_pkt_icmp = (sr_icmp_hdr_t *)(send_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          memcpy(send_pkt_eth->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
        	memcpy(send_pkt_eth->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
          send_pkt_eth->ether_type = htons(ethertype_ip);

          send_pkt_ip->ip_tos = iphdr->ip_tos;
          send_pkt_ip->ip_len = (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
          send_pkt_ip->ip_id = iphdr->ip_id;
          send_pkt_ip->ip_off = 0;
          send_pkt_ip->ip_ttl = 255;
          send_pkt_ip->ip_p = 1;
          send_pkt_ip->ip_sum = 0;
          uint32_t ip_new_src = iphdr->ip_src;;
          send_pkt_ip->ip_src = iphdr->ip_dst;
          send_pkt_ip->ip_dst = ip_new_src;
              
          send_pkt_ip->ip_sum = cksum(send_pkt_ip, sizeof(sr_ip_hdr_t));

          send_pkt_icmp->icmp_type = 3;
          send_pkt_icmp->icmp_code = 3;
          send_pkt_icmp->icmp_sum = cksum(send_pkt_icmp, sizeof(sr_icmp_hdr_t));
	      
	      fprintf(stderr,"Attempting to send the following ICMP Port unreachable packet\n");
		print_hdrs(send_pkt, send_pkt_len);

          sr_send_packet(sr, send_pkt, send_pkt_len, interface);
	  free(send_pkt);
      }
    /* if the packet is NOT destined for this router */
    } else {
	/* Check if ttl is <= 1. if it is respond with ICMP time exceeded */
	if (iphdr->ip_ttl <= 1){
	    uint32_t send_pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
          uint8_t *send_pkt = (uint8_t *)malloc(send_pkt_len);

          sr_ethernet_hdr_t *send_pkt_eth = (sr_ethernet_hdr_t *)send_pkt;
          sr_ip_hdr_t *send_pkt_ip = (sr_ip_hdr_t *)(send_pkt + sizeof(sr_ethernet_hdr_t));
          sr_icmp_hdr_t *send_pkt_icmp = (sr_icmp_hdr_t *)(send_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          memcpy(send_pkt_eth->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
        	memcpy(send_pkt_eth->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
          send_pkt_eth->ether_type = htons(ethertype_ip);

          send_pkt_ip->ip_tos = iphdr->ip_tos;
          send_pkt_ip->ip_len = (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
          send_pkt_ip->ip_id = iphdr->ip_id;
          send_pkt_ip->ip_off = 0;
          send_pkt_ip->ip_ttl = 255;
          send_pkt_ip->ip_p = 1;
          send_pkt_ip->ip_sum = 0;
          uint32_t ip_new_src = iphdr->ip_src;;
          send_pkt_ip->ip_src = iphdr->ip_dst;
          send_pkt_ip->ip_dst = ip_new_src;
              
          send_pkt_ip->ip_sum = cksum(send_pkt_ip, sizeof(sr_ip_hdr_t));

          send_pkt_icmp->icmp_type = 11;
          send_pkt_icmp->icmp_code = 0;
          send_pkt_icmp->icmp_sum = cksum(send_pkt_icmp, sizeof(sr_icmp_hdr_t));

		fprintf(stderr,"Attempting to send the following ICMP Time Exceeded packet\n");
		print_hdrs(send_pkt, send_pkt_len);
		
          sr_send_packet(sr, send_pkt, send_pkt_len, interface);
	free(send_pkt);
	    } else {
      	/* check routing table for longest matching prefix IP address */
	int isOnRoutingTable = 0;
	struct sr_rt* rt_entry = 0;
		
	struct sr_rt* rt_walker = 0;

    	rt_walker = sr->routing_table;
    
    	while(rt_walker->next){
        	rt_walker = rt_walker->next;
        	if (iphdr->ip_dst == rt_walker->dest.s_addr){
          	isOnRoutingTable = 1;
		rt_entry = rt_walker;
        	}
    	}
	if(isOnRoutingTable == 0){
        	/* if there is not a match respond ICMP network unreachable */
	    uint32_t send_pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
          uint8_t *send_pkt = (uint8_t *)malloc(send_pkt_len);

          sr_ethernet_hdr_t *send_pkt_eth = (sr_ethernet_hdr_t *)send_pkt;
          sr_ip_hdr_t *send_pkt_ip = (sr_ip_hdr_t *)(send_pkt + sizeof(sr_ethernet_hdr_t));
          sr_icmp_hdr_t *send_pkt_icmp = (sr_icmp_hdr_t *)(send_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          memcpy(send_pkt_eth->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
        	memcpy(send_pkt_eth->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
          send_pkt_eth->ether_type = htons(ethertype_ip);

          send_pkt_ip->ip_tos = iphdr->ip_tos;
          send_pkt_ip->ip_len = (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
          send_pkt_ip->ip_id = iphdr->ip_id;
          send_pkt_ip->ip_off = 0;
          send_pkt_ip->ip_ttl = 255;
          send_pkt_ip->ip_p = 1;
          send_pkt_ip->ip_sum = 0;
          uint32_t ip_new_src = iphdr->ip_src;;
          send_pkt_ip->ip_src = iphdr->ip_dst;
          send_pkt_ip->ip_dst = ip_new_src;
              
          send_pkt_ip->ip_sum = cksum(send_pkt_ip, sizeof(sr_ip_hdr_t));

          send_pkt_icmp->icmp_type = 3;
          send_pkt_icmp->icmp_code = 0;
          send_pkt_icmp->icmp_sum = cksum(send_pkt_icmp, sizeof(sr_icmp_hdr_t));
		
		fprintf(stderr,"Attempting to send the following ICMP Network unreachable packet\n");
		print_hdrs(send_pkt, send_pkt_len);

          sr_send_packet(sr, send_pkt, send_pkt_len, interface);
	free(send_pkt);
	} else{
	/* decrement the ttl & recalculate checksum */
          iphdr->ip_ttl -= 1;
	iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
        /* if there is a match check the ARP cache for MAC address */
	struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache),rt_entry->dest.s_addr);
          /* if there is a miss send an ARP request to the IP dest*/
	if(arp_entry == 0){
            sr_waitforarp(sr,packet,len,iphdr->ip_dst,sr_get_interface(sr,rt_entry->interface));
	}
	arp_entry = sr_arpcache_lookup(&(sr->cache),iphdr->ip_dst);
	if(arp_entry == 0){
		/* if there is not a match respond ICMP host unreachable */
	    uint32_t send_pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
          uint8_t *send_pkt = (uint8_t *)malloc(send_pkt_len);

          sr_ethernet_hdr_t *send_pkt_eth = (sr_ethernet_hdr_t *)send_pkt;
          sr_ip_hdr_t *send_pkt_ip = (sr_ip_hdr_t *)(send_pkt + sizeof(sr_ethernet_hdr_t));
	
          memcpy(send_pkt_eth->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(send_pkt_eth->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
          send_pkt_eth->ether_type = htons(ethertype_ip);

          send_pkt_ip->ip_tos = iphdr->ip_tos;
          send_pkt_ip->ip_len = (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
          send_pkt_ip->ip_id = iphdr->ip_id;
          send_pkt_ip->ip_off = 0;
          send_pkt_ip->ip_ttl = 255;
          send_pkt_ip->ip_p = 1;
          send_pkt_ip->ip_sum = 0;
	uint32_t ip_new_src = iphdr->ip_src;;
          send_pkt_ip->ip_src = iphdr->ip_dst;
          send_pkt_ip->ip_dst = ip_new_src;
              
          send_pkt_ip->ip_sum = cksum(send_pkt_ip, sizeof(sr_ip_hdr_t));
		
		fprintf(stderr,"Attempting to send the following ICMP Host unreachable packet\n");
		print_hdrs(send_pkt, send_pkt_len);

          sr_send_packet(sr, send_pkt, send_pkt_len, interface);
	free(send_pkt);
	}else{
          /* if there is a hit use the IP and MAC info to forward to next hop */
	memcpy(ehdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
	memcpy(ehdr->ether_shost, (sr_get_interface(sr,rt_entry->interface))->addr, ETHER_ADDR_LEN);

		fprintf(stderr,"Attempting to forward the following packet\n");
		print_hdrs(packet, len);
		
        sr_send_packet(sr, packet, len, rt_entry->interface);
	}
	}
	}
    } 

      break;

      /* If neither */
      fprintf(stderr, "Failed to parse packet, unsupported ethertype\n");      
    }
  /*************************************************************************/

}/* end sr_ForwardPacket */
