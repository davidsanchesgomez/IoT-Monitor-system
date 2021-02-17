/********************************************************
* COAP pcap reader and parser                           *
* Start date: 19/09/2020		                        *
* Author: David Sanches Gómez                           *
* Compila: gcc -Wall -o coap coap.c -lpcap              *
*********************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
/*****************Constants definitions*****************/
#define PACK_READ 1
#define TRACE_END -2
#define OK 0
#define ERROR 1
#define ETH_HLEN 14 /* Tamanio de la cabecera ethernet*/
#define ETH_ALEN 6		//Ethernet direction  
#define IP_ALEN 4
#define UDP_HLEN 8

//hash
#include <stdbool.h>
#define SIZE 10000 
/*******************************************************/

/*****************Constants definitions*****************/
#define PACK_READ 1
#define TRACE_END -2
#define OK 0
#define ERROR 1
#define ETH_HLEN      14 /* Tamanio de la cabecera ethernet*/
#define ETH_ALEN 6		//Ethernet direction  
#define IP_ALEN 4
#define code_empty 0
#define code_get 1
#define code_post 2
#define code_put 3
#define code_delete 4
#define code_ok 64
#define code_created 65
#define code_deleted 66
#define code_valid 67
#define code_charged 68
#define code_content 69
#define code_badrequest 128
#define code_unathorized 129
#define code_badoption 130
#define code_forbiden 131
#define code_notfound 132
#define code_methodenotallowed 133
#define code_requestentitytoolarge 141
#define code_unsupportedmediatype 143
#define code_internalservererror 160
#define code_notimplemented 161
#define code_badgateway 162
#define code_serviceunavailable 163
#define code_gatewaytimeout 164
#define code_proxyingnotsupported 165
/*******************************************************/

pcap_t *descr = NULL;

/*****************Structure definitions*****************/

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETH_ALEN]; 		/* Destination host address */
	u_char ether_shost[ETH_ALEN]; 		/* Source host address */		
	u_short ether_type; 				/* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;				/* version << 4 | header length >> 2 */
	u_char ip_tos;				/* type of service */
	u_short ip_len;				/* total length */
	u_short ip_id;				/* identification */
	u_short ip_off;				/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;				/* time to live */
	u_char ip_p;				/* protocol */
	u_short ip_sum;				/* checksum */
	u_char ip_src[IP_ALEN];
	u_char ip_dst[IP_ALEN]; 	/* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)


/* UDP header */
struct sniff_udp {
	u_short udp_sport;	/* source port */
	u_short udp_dport;	/* destination port */
	u_short udp_len;	/* length */
	u_short udp_sum;	/*checksum*/
};

/*COAP header*/
struct sniff_coap{
	uint8_t control;	//version 2bits, type 2bits, token length 4bits
	uint8_t code;
	uint16_t message_id;
};

struct sniff_coap_options1{
	uint8_t option_delta_length;
	char uri[];
};

struct sniff_coap_options2{
	uint8_t option_delta_length;
	char uri[];
};

struct sniff_coap_endoptions{
	uint8_t end_options_marker;
};



char* code (uint8_t code_number){
	char* code;
	switch (code_number) {
		case code_empty: {
        	code ="Empty_Message";
            return(code);
        }
        case code_get: {
        	code ="GET";
            return(code);
        }
        case code_post: {
        	code ="POST";
            return(code);
        }
        case code_put: {
        	code ="PUT";
            return(code);
        }
        case code_delete: {
        	code ="DELETE";
            return(code);
        }
        case code_ok: {
        	code ="2.00_OK";
            return(code);
        }
        case code_created: {
        	code ="2.01_Created";
            return(code);
        }
        case code_deleted: {
        	code ="2.02_Deleted";
            return(code);
        }
        case code_valid: {
        	code ="2.03_Valid";
            return(code);
        }
        case code_charged: {
        	code ="2.04_Charged";
            return(code);
        }
        case code_content: {
        	code ="2.05_Content";
            return(code);
        }
        case code_badrequest: {
        	code ="4.00_Bad_Request";
            return(code);
        }
        case code_unathorized: {
        	code ="4.01_Unauthorized";
            return(code);
        }
        case code_badoption: {
        	code ="4.02_Bad_Option";
            return(code);
        }
        case code_forbiden: {
        	code ="4.03_Forbiden";
            return(code);
        }
        case code_notfound: {
        	code ="4.04_Not_Found";
            return(code);
        }
        case code_methodenotallowed: {
        	code ="4.05_Methode_Not_Allowed";
            return(code);
        }
        case code_requestentitytoolarge: {
        	code ="4.13_Request_Entity_Too_Large";
            return(code);
        }
        case code_unsupportedmediatype: {
        	code ="4.15_Unsupported_Media_Type";
            return(code);
        }
        case code_internalservererror: {
        	code ="5.00_Internal_Server_Error";
            return(code);
        }
        case code_notimplemented: {
        	code ="5.01_Not_Implemented";
            return(code);
        }
        case code_badgateway: {
        	code ="5.02_Bad_Gateway";
            return(code);
        }
        case code_serviceunavailable: {
        	code ="5.03_Service_Unavailable";
            return(code);
        }
        case code_gatewaytimeout: {
        	code ="5.04_Gateway_Timeout";
            return(code);
        }
        case code_proxyingnotsupported: {
        	code ="5.05_Proxying_Not_Supported";
            return(code);
        }

    }
    return("fail");
}



/**********************Hash Ip**************************/
//Genereate the struct of the variables you want to store
typedef struct node {
   	uint8_t ipsrc[IP_ALEN];
	uint8_t ipdst[IP_ALEN];
	char *Packet_type_coap;
	double init_time;
	double answer_delay;
	char *code;
	uint16_t message_id;
	uint16_t port_src;
	uint16_t port_dst;
    int bytes;
	int version;
	char *uri_path;
	char *uri_path2;
	char *uri_host;
	char *uri_host2;

	struct node* next;
}node;


node *hashTable[10000];
int hashTableSize = 10000;
double first_packet_time_arrival;

int searchNode(int key, uint8_t ipsrc[IP_ALEN], uint8_t ipdst[IP_ALEN], int message_id){
	node *n;
	key=key%hashTableSize;
	
	for(n=hashTable[key]; n != NULL; n=n->next){
		if(((n->ipsrc[0]==ipsrc[0] && n->ipsrc[1]==ipsrc[1] && n->ipsrc[2]==ipsrc[2] && n->ipsrc[3]==ipsrc[3] && n->ipdst[0]==ipdst[0] && n->ipdst[1]==ipdst[1] && n->ipdst[2]==ipdst[2] && n->ipdst[3]==ipdst[3]) || (n->ipdst[0]==ipsrc[0] && n->ipdst[1]==ipsrc[1] && n->ipdst[2]==ipsrc[2] && n->ipdst[3]==ipsrc[3] && n->ipsrc[0]==ipdst[0] && n->ipsrc[1]==ipdst[1] && n->ipsrc[2]==ipdst[2] && n->ipsrc[3]==ipdst[3])) && (n->message_id==message_id)){   //search if key is same, if it is then search if same "flujo", if not is a colision, go next
			first_packet_time_arrival=n->init_time;
			return rand() % 1000 + 1;
		}
	}
	return -1;
}

void insert_IP(int key, uint8_t ipsrc[IP_ALEN], uint8_t ipdst[IP_ALEN], int Packet_type_coap, double time_microsec, double first_packet_time, char *code, uint16_t message_id, uint16_t port_src, uint16_t port_dst, int bytes, int version, char *uri_path, char *uri_path2, char *uri_host, char *uri_host2){
	node *new_node, *n1;
	new_node=(node*)malloc(sizeof(node));
	
	new_node->ipsrc[0]=ipsrc[0];
    for (int i = 1; i < IP_ALEN; i++) {
			new_node->ipsrc[i]=ipsrc[i];
	}
	new_node->ipdst[0]=ipdst[0];
    for (int i = 1; i < IP_ALEN; i++) {
			new_node->ipdst[i]=ipdst[i];
	}
	if (Packet_type_coap==0){
		new_node->Packet_type_coap="CONFIRMABLE";
	}
	if (Packet_type_coap==1){
		new_node->Packet_type_coap="NON-CONFIRMABLE";
	}
	if (Packet_type_coap==2){
		new_node->Packet_type_coap="AKNOWLEDGEMENT";
	}
	if (Packet_type_coap==3){
		new_node->Packet_type_coap="RESET";
	}
	new_node->code=code;
	new_node->init_time=time_microsec;
	new_node->answer_delay=time_microsec-first_packet_time;
	new_node->message_id=message_id;
	new_node->port_src=port_src;
    new_node->port_dst=port_dst;
    new_node->bytes=bytes;
	new_node->version=version;
	new_node->uri_host=uri_host;
	new_node->uri_host2=uri_host2;
	new_node->uri_path=uri_path;
	new_node->uri_path2=uri_path2;

	new_node->next=NULL;
	
	key=key%hashTableSize;
	if(hashTable[key] == NULL)
	{
		hashTable[key]=new_node;
	}
	else{
		for(n1=hashTable[key]; n1->next !=NULL; n1=n1->next);
		n1->next=new_node;
	}
}



void printlist(node *n,  FILE *f){

	node *n1;
	for(n1=n; n1!=NULL; n1=n1->next){

		struct tm  ts;
		char       buf[80];
		const time_t bar = n1->init_time;
    	ts = *localtime((&bar));

		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ts);
		fprintf(f,"%s;", buf);

		fprintf(f,"%d;",n1->message_id);

		fprintf(f,"%s;", n1->Packet_type_coap);

		fprintf(f,"%d.%d.%d.%d;%d.%d.%d.%d;%d;%d;", n1->ipsrc[0], n1->ipsrc[1], n1->ipsrc[2], n1->ipsrc[3], n1->ipdst[0], n1->ipdst[1], n1->ipdst[2], n1->ipdst[3], n1->port_src, n1->port_dst);
		
		fprintf(f,"%s;", n1->code);
		
		fprintf(f,"%lf;", n1->answer_delay);

		fprintf(f,"%d;", n1->bytes);

		fprintf(f,"%d;", n1->version);

		if (strcmp(n1->uri_host,"") == 0){
			fprintf(f,";");	
		}else {
			fprintf(f,"%s/%s;", n1->uri_host, n1->uri_host2);}
		 
		if ((strcmp(n1->uri_path,"") == 0) && (strcmp(n1->uri_path2,"") == 0)){
			fprintf(f,";");	
		}
		else {
			fprintf(f,"%s/%s;", n1->uri_path, n1->uri_path2);
		}

		fprintf(f,"\n");					
	}
	 
}

void printHashtable( FILE *f){
	fprintf(f,"Init_time;Message_id;Packet_type;IP_src;IP_dst;Port_src;Port_dst;Code;RTT;Bytes;Version;Uri_host;Uri_path\n");
	for(int i=0; i<hashTableSize; i++){
		printlist(hashTable[i], f);
	}
}
/*******************************************************/

void packet_analyzer(const struct pcap_pkthdr *hdr, const uint8_t *pack, int link_layer)
{
	uint8_t ip_src[IP_ALEN], ip_dst[IP_ALEN];
	uint16_t aux16_sport, aux16_dport, aux16;
	int Packet_type_coap, size_ip, protocolo, i, key_IP, hashfind, Total_length, byteLength, version, op_delta, op_length, op_delta2, op_length2, token_length;
	double microseconds, seconds, epochtime;

	microseconds=hdr->ts.tv_usec;
	seconds=hdr->ts.tv_sec;
	epochtime=seconds+microseconds/1000000;

	if (link_layer==1){	//Ethernet link layer
		//IP header
		const struct sniff_ip *ip; 
		ip = (struct sniff_ip*)(pack + ETH_HLEN);

		size_ip = IP_HL(ip)*4;

		memcpy(&aux16,&ip->ip_len,sizeof(uint16_t));
		Total_length=ntohs(aux16);
	    byteLength=Total_length+ETH_HLEN;
	
		protocolo=ip->ip_p;
        
		ip_src[0]=ip->ip_src[0];
		for (i = 1; i < IP_ALEN; i++) {
			ip_src[i]=ip->ip_src[i];
		}
        
		ip_dst[0]=ip->ip_dst[0];
		for (i = 1; i < IP_ALEN; i++) {
			ip_dst[i]=ip->ip_dst[i];
		}


		if (protocolo==17){   // udp

			

			const struct sniff_udp *udp; /* The UDP header */
			udp = (struct sniff_udp*)(pack + ETH_HLEN  + size_ip);

			memcpy(&aux16_sport,&udp->udp_sport,sizeof(uint16_t));
			
			memcpy(&aux16_dport,&udp->udp_dport,sizeof(uint16_t));
			
            
			char *uri_path="";
			char *uri_path2="";
			char *uri_host="";
			char *uri_host2="";

			if (ntohs(aux16_sport)==5683 || ntohs(aux16_dport)==5683){

				
				const struct sniff_coap *coap; 
				coap = (struct sniff_coap*)(pack + ETH_HLEN  + size_ip + UDP_HLEN);
				
				version = ((coap->control & 0xc0)>>6);
				
				Packet_type_coap = ((coap->control & 0x30)>>4);

				token_length = (coap->control & 0x0f);

				if ((coap->code ==  1) ||  (coap->code ==  2) || (coap->code ==  3) || (coap->code ==  4) || (coap->code ==  69) ){
					const struct sniff_coap_options1 *coapOptions; 
					coapOptions = (struct sniff_coap_options1*)(pack + ETH_HLEN  + size_ip + UDP_HLEN + 4 + token_length);

					op_delta=((coapOptions->option_delta_length & 0xf0)>>4);
					op_length=(coapOptions->option_delta_length & 0x0f);

					if (op_delta==0x8){//0xb
						
						uri_path=(char *) malloc(op_length);
						strcat(uri_path, coapOptions->uri);
						uri_path[sizeof(uri_path)-1]='\0';
						
					}
					if (op_delta==0x3){
						uri_host=(char *) malloc(op_length);						
						strcat(uri_host, coapOptions->uri);
						uri_host[sizeof(uri_host)-1]='\0';
						
					}
					
					const struct sniff_coap_endoptions *optionsmarker; 
					optionsmarker = (struct sniff_coap_endoptions*)(pack + ETH_HLEN  + size_ip + UDP_HLEN + 4 + token_length + 1 + op_length);

					if (optionsmarker->end_options_marker !=0xff){
						
						const struct sniff_coap_options2 *coapOptions2; 
						coapOptions2 = (struct sniff_coap_options2*)(pack + ETH_HLEN  + size_ip + UDP_HLEN +4 + token_length + 1 + op_length);
						op_delta2=((coapOptions2->option_delta_length & 0xf0)>>4);
						op_length2=(coapOptions2->option_delta_length & 0x0f);
						 ;
						if (op_delta2==0x8){
							uri_path2=(char *) malloc(op_length2);
							strcat(uri_path2, coapOptions2->uri);
							uri_path2[sizeof(uri_path2)-1]='\0';
						}
						if (op_delta2==0x3){
							uri_host2=(char *) malloc(op_length2);
							strcat(uri_host2, coapOptions2->uri);
							uri_host2[sizeof(uri_host2)-1]='\0';
							
						}
					}
				}


				key_IP=ip_src[0]+ip_src[1]+ip_src[2]+ip_src[3]+ip_dst[0]+ip_dst[1]+ip_dst[2]+ip_dst[3] + ntohs(aux16_dport) +ntohs(aux16_sport) - 5683;	//i substract the port that is common to all coap packets, not worth it
				hashfind=searchNode( key_IP, ip_src, ip_dst, ntohs(coap->message_id));
				if(hashfind == -1){						
					insert_IP(key_IP, ip_src, ip_dst, Packet_type_coap, epochtime, epochtime, code(coap->code), ntohs(coap->message_id),ntohs(aux16_sport), ntohs(aux16_dport), byteLength, version, uri_path, uri_path2, uri_host, uri_host2);
				}else{
					key_IP=hashfind*100000+ip_src[0]+ip_src[1]+ip_src[2]+ip_src[3]+ip_dst[0]+ip_dst[1]+ip_dst[2]+ip_dst[3] + ntohs(aux16_dport) +ntohs(aux16_sport) - 5683;	//i substract the port that is common to all coap packets, not worth it
					insert_IP(key_IP, ip_src, ip_dst, Packet_type_coap, epochtime, first_packet_time_arrival, code(coap->code), ntohs(coap->message_id),ntohs(aux16_sport), ntohs(aux16_dport), byteLength, version, uri_path, uri_path2, uri_host, uri_host2);
				}

				
			}
		}
	}

	/*if (link_layer==104){	//IEEE 802.15.4 wirless Pan, Cisco
		

	}*/


}
int main(int argc, char **argv)
{
	uint8_t *pack = NULL;
	struct pcap_pkthdr *hdr;
	char errbuf[PCAP_ERRBUF_SIZE];
	char entrada[256];		//archivo pcap que queremos leer
	
	int long_index = 0, retorno = 0, link_layer;
	char opt;		
	//REGISTRO
	FILE *f = fopen("registerCOAP.csv","w");
	//Comprobamos que se le pasa un archivo, si no ocurre se para la ejecución y se muestra como hacerlo
	if (argc > 1) {
		if (strlen(argv[1]) < 256) {
			strcpy(entrada, argv[1]);
		}

	} else {
		printf("Ejecucion: %s <-f traza.pcap \n", argv[0]);
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {

		switch (opt) {

			case 'f' :
				if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
					printf("Ha seleccionado más de una fuente de datos\n");
					pcap_close(descr);
					exit(ERROR);
				}
				
				if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
					printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
					exit(ERROR);
				}

				break;

			
			case '?' :
			default:
				printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
				break;
		}
	}

	if (!descr) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	link_layer=pcap_datalink(descr);	//returns the link-layer header type for the live capture 

	do{
		retorno = pcap_next_ex(descr, &hdr, (const u_char **)&pack);
		if (retorno == PACK_READ) { //Todo correcto
				packet_analyzer(hdr, pack, link_layer);				
		}

	} while (retorno != TRACE_END);

	printHashtable(f);

	return OK;
}