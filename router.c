#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <unistd.h>
#include <arpa/inet.h> 
#include <ctype.h>
#include <string.h>

/*TIPURI DE PACHETE*/
#define IPV4 0x0800
#define ARP  0x0806

/* Routing table */
struct route_table_entry *routing_table;
int routing_table_len;

/* Arp table */
struct arp_entry *arp_table;
int arp_table_len;


struct arp_entry *get_arp_entry(uint32_t ip_dest) {
	
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip_dest) {
			return &arp_table[i];
		}
	}
	return NULL;
}


/*Pasul 3: calcul lpm cu binary search si routing table sortat crescator*/
struct route_table_entry *longest_prefix_match(uint32_t ip_dest) {

	int left = 0;
	int right = routing_table_len - 1;
	int bestRoute_index = -1;

	while (left <= right) {
		int middle = (left + right) / 2;

		/*trb sa schimb in host order, valorile ordonate sunt tot in norder*/
		int prefix_result = ntohl(ip_dest & routing_table[middle].mask);
		int prefix_current = ntohl(routing_table[middle].prefix);

		/*retin mereu indexul prefixului gasit, vectorul fiind ord crescator la final voi avea longest prefix*/
		if ( prefix_result == prefix_current ) {
			bestRoute_index = middle;
			left = middle + 1;

		} else {
			
			/*decizie continuare cautare*/
			if ( prefix_result > prefix_current ) {
				left = middle + 1;
			} else {
				right = middle - 1;
			}
		}
	}
	
	if (bestRoute_index != -1) {
		return &routing_table[bestRoute_index];
	}

	return NULL;
}

/*trebuie sa transform network si host entryurile pt a face corect fct compare la qsort
-sortez dupa masca in ord crescatoare, pt masti egale sortez dupa prefix crescator*/

int compare_function(const void *first, const void *second) {

	struct route_table_entry first_entry = *(struct route_table_entry *) first;
	struct route_table_entry second_entry = *(struct route_table_entry *) second;

	if (first_entry.mask != second_entry.mask) {
		return ntohl(first_entry.mask) - ntohl(second_entry.mask);
	} else {
		return ntohl(first_entry.prefix) - ntohl(second_entry.prefix);
	}
}



/*construire pachet*/

char* build_ARP_packet (uint32_t dest_ip ,uint32_t source_ip, uint8_t source_mac[6],
                uint8_t dest_mac[6], uint16_t arp_action) {
	/*generare packet*/
	char* packet= malloc(sizeof(struct ether_header) + sizeof(struct arp_header));

	/*ETHERNET HEADER*/
	struct  ether_header ethernet_header;
	memcpy(ethernet_header.ether_dhost, dest_mac, 6);
	memcpy(ethernet_header.ether_shost, source_mac, 6);
	ethernet_header.ether_type = htons(ARP);
	

	/*ARP HEADER*/
	/*init + alocare campuri ARP HEADER pt packet*/
	/*host to network!*/
    struct arp_header arp_header;
	arp_header.htype = htons(1);
	arp_header.ptype = htons(IPV4); 
	arp_header.hlen = 6;
	arp_header.plen = 4; 		//protoc este IPV4 - 32 biti
	arp_header.op = arp_action;// 1 - request/ 2 -reply
	/*MAC*/
    memcpy(arp_header.sha, ethernet_header.ether_shost, 6);
    memcpy(arp_header.tha, ethernet_header.ether_dhost, 6); 
    /*IP*/
    arp_header.spa = source_ip;
    arp_header.tpa = dest_ip;

	/*initializare in packet*/
	memcpy(packet, &ethernet_header, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), &arp_header, sizeof(struct arp_header));
	
	return packet;
}



/*un arp request il face un pachet sursa buf de tip IPV4 care vrea sa trimita info la 
un nod de retea aflat al carui MAC nu il stie*/

void ARP_request(struct packet_info *buf_info) {

	/*pachetul sursa: buf*/
	struct ether_header *ethdr_buf = (struct ether_header *) buf_info->buf;
	struct iphdr *ipHdr_buf = (struct iphdr *)(buf_info->buf + sizeof(struct ether_header));


	/*init + alocare campuri ENTHERNET HEADER pt packet*/
    uint8_t dest_mac[6];      /*init destinatie cu broadcast*/
	memset(dest_mac, 0xFF, 6);
    uint8_t source_mac[6];
	memcpy(source_mac, ethdr_buf->ether_shost, 6);

	
	uint32_t dest_ip = buf_info->next_hop;
    get_interface_mac(buf_info->best_route_interface, source_mac); //init sursa

	/*adr ip sursa = a routerului*/
	uint32_t source_ip = inet_addr(get_interface_ip(buf_info->best_route_interface));
	

	/*consturiesc pachet*/
	char packet[MAX_PACKET_LEN];
    memcpy(packet, build_ARP_packet(dest_ip, source_ip, source_mac, dest_mac,
                						htons(1)), MAX_PACKET_LEN);

	/*trimit packetul pe interfata ceruta*/
	int len_packet = sizeof(struct ether_header) + sizeof(struct arp_header);
	send_to_link(buf_info->best_route_interface, packet, len_packet);
}


/* ARP reply */
void reply_ARP(char buf[MAX_PACKET_LEN], int interface) {

    struct arp_header *arp_header = (struct arp_header *)(buf + sizeof(struct ether_header));

 
    /*B trebuie sa ii raspunda lui A cu adr mac, A - sursa init devine dest
	* adresa mac/ip a lui A se gasesc in arp header din pachet in campurile
	*sender*/

 	/*ETHERNET HEADER*/
    uint32_t dest_ip = arp_header->spa;
	uint8_t dest_mac[6];
    memcpy(dest_mac, arp_header->sha, 6);

	/*sursa = fostul target*/
    uint32_t source_ip = arp_header->tpa;
    uint8_t source_mac[6];
	/*macului lui B */
	get_interface_mac(interface, source_mac);
    

	/*noul pachet*/
	char packet[MAX_PACKET_LEN];
    memcpy(packet, build_ARP_packet(dest_ip, source_ip, source_mac, dest_mac, htons(2)),
				MAX_PACKET_LEN);

	int len_packet = sizeof(struct ether_header) + sizeof(struct arp_header);
	send_to_link(interface, packet, len_packet);
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	/*alocare*/
	routing_table = malloc(sizeof(struct route_table_entry) * 100000);
	arp_table = malloc(sizeof(struct arp_entry) * 100000);

	/*Initializari tabele + coada*/ //////DE PUS ALT NUME LA TABELA
	routing_table_len = read_rtable(argv[1], routing_table);
	queue queue_packets = queue_create();

	/*sortare cu qsort tabel rutare pt a face LPM cu binary search*/
	qsort(routing_table, routing_table_len, sizeof(struct route_table_entry), compare_function);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		
		/*PACHET IPV4*/

		if( (ntohs(eth_hdr->ether_type)) == IPV4 ) {

		/*PAS 0: vf router = destinatie ICMP TODO */

		/*PAS 1: verifica checksum */

		struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
        uint16_t old_sum = ip_header->check;
		ip_header->check = 0;
		uint16_t result_host = checksum((uint16_t *)ip_header, sizeof(struct iphdr));
		uint16_t result_net = htons(result_host);

		
		if(old_sum != result_net ) {
			memset(buf, 0, sizeof(buf));
			continue;
		}

		/*PAS 2: TTL vf + vf icmp (TO DO)*/

		if(ip_header->ttl <= 1) {
			continue;
		}

		/* decremenetez ttl + actualizare checksum cu noul ttl  */

		uint16_t old_ttl = ip_header->ttl;
		ip_header->ttl--;
		uint16_t new_sum = ~(~old_sum +  ~((uint16_t)old_ttl) + (uint16_t)ip_header->ttl) - 1;
		ip_header->check = new_sum;


		/*PAS 4: cautare tabel rutare cu LPM */
		struct route_table_entry *best_route = longest_prefix_match(ip_header->daddr);
		if(best_route == NULL) {
			continue;
		}

		
		/*Pas 5: *daca exista in arp table intrarea pt best route - trec la urmatorul HOP 
				*daca nu exista=> nevoie de ARP request BROADCAST
				*pachetul asteapta un ARP reply => intra in coada*/

		struct arp_entry *next_hop = get_arp_entry(best_route->next_hop);
		if (next_hop == NULL) {
			struct packet_info *buf_info = malloc(sizeof (struct packet_info));
	
			memcpy(buf_info->buf, buf, MAX_PACKET_LEN);
			buf_info->len = len;
			buf_info->best_route_interface = best_route->interface;
			buf_info->next_hop = best_route->next_hop;

			queue_enq(queue_packets, buf_info); /*adaug in coada pachetul si request ARP*/
			ARP_request(buf_info);   			/*pe structura mea*/
			continue;
		}

		/*Pas 6: adr mac veche devine cea gasita de urmatorul hop*/
		uint8_t *old_mac = (uint8_t *)eth_hdr->ether_dhost;
		memcpy(old_mac, next_hop->mac, sizeof(eth_hdr->ether_dhost));
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);
		  

		/*Pas final 7: trimitere pachet pe interfata hopului*/
		send_to_link(best_route->interface, buf, len);

		}

		
		/*Pt pachetul de ARP:*/

		if ((ntohs(eth_hdr->ether_type)) == ARP) {

			struct arp_header *arp_header = (struct arp_header *)(buf + sizeof(struct ether_header));

			/*interceptez pachet arp request => trb sa am un arp reply cu acel MAC addr
			*vf daca adresa target ceruta */
			if (arp_header->op == ntohs(1)) {
				reply_ARP(buf, interface);
				continue;
			}


			/*arp reply => trb sa scot din coada pachetul*/
			/*  adaug in cache arp o noua intrare tip: spa/sha
				SPA = sender IP Addres
				SHA = sender hardware Address - MAC address
			*/
			if ((ntohs(arp_header->op)) == 2) {
				struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
				memcpy(&new_entry->ip, &arp_header->spa, sizeof(arp_header->spa));
				memcpy(&new_entry->mac, &arp_header->sha, sizeof(arp_header->sha));

				uint32_t ok = 0;
				for (uint32_t i = 0; i < arp_table_len; i++) {
					if (new_entry->ip == arp_table[i].ip) {
						ok = 1;
						break;
					}
				}

				/*nu am intrarea => se adauga la finalul tabelei*/
				if (ok == 0) {
					memcpy(&arp_table[arp_table_len], new_entry,
						   sizeof(struct arp_entry));
					arp_table_len++;
				}

				/*scot din coada pachetul */
				queue new_queue =  queue_create();
				while ( !queue_empty(queue_packets) ) {
					struct packet_info *packet_info = queue_deq(queue_packets);
					uint32_t next_hop = packet_info->next_hop;
					
					struct arp_entry *arp_entry = get_arp_entry(next_hop);
					if ( arp_entry == NULL ) {
						queue_enq(new_queue, packet_info);
					}
					
					/*trimit pachetele actualizate cu destinatia mac a best route ului*/
        			struct ether_header *ether_h = (struct ether_header *) packet_info->buf;
        			memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);
					send_to_link(packet_info->best_route_interface, packet_info->buf, packet_info->len);
				}

				while ( !queue_empty(new_queue) ) {
					struct packet_info *packet_info = queue_deq(queue_packets);
					queue_enq(queue_packets, packet_info);
				}
										   
				continue;
			}
		}

	}
}