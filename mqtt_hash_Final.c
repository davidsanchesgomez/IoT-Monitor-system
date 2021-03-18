/********************************************************
* MQTT pcap reader and parser                           *
* Start date: 5/08/2020		                        *
* Author: David Sanches Gómez                           *
* Compila: gcc -Wall -o mqtt mqtt.c -lpcap              *
*********************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>
/*****************Constants definitions*****************/
#define PACK_READ 1
#define TRACE_END -2
#define OK 0
#define ERROR 1
#define ETH_HLEN      14 /* Tamanio de la cabecera ethernet*/
#define ETH_ALEN 6		//Ethernet direction  
#define IP_ALEN 4
/*******************************************************/

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

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

	

	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};


/*MQTT fixed header*/
struct sniff_mqtt {
	uint8_t control;    //Control Field. First 4 Packet Type, next Flags
	u_char packet_length;  //MSB used as a continuation flag

};

/*MQTT connect command variables*/
struct sniff_mqtt_connect_1{
	uint16_t protocol_name_length;
	char protocol_name[];
	
};
struct sniff_mqtt_connect_2{
	uint8_t version;
	uint8_t flags;
	uint16_t keep_alive;
	uint16_t client_id_length;
	char client_id[];	
};
struct sniff_mqtt_connect_3{	
	uint16_t user_name_length;
	char user_name[];	
};
struct sniff_mqtt_connect_4{
	uint16_t password_length;
	char password[];	
};

/*MQTT Connect ACK*/
struct sniff_mqtt_ack{
	uint8_t reserved;
	uint8_t return_code;
};

/*MQTT Publish Message*/
struct sniff_mqtt_publish{
	uint16_t topic_length;
	char topic[];
};
struct sniff_mqtt_publish_2{
	uint8_t auxiliary_variable;	//to get rid of the error of flexible array member in a struct with no named members (we add 1 byte less so it doesnt affect)
	char message[];
};

/*MQTT Subscribe Request*/
struct sniff_mqtt_subscribe_req{
	uint16_t message_identifier;

};

/*******************************************************/

/*****************Global variables**********************/

pcap_t *descr = NULL;
int throughput=0;


/*******************************************************/




/**********************Hash Ip**************************/
//Genereate the struct of the variables you want to store
typedef struct node {
   	uint8_t ipsrc[IP_ALEN];
	uint8_t ipdst[IP_ALEN];
	char *Packet_type_mqtt;
	uint16_t portsrc;
    uint16_t portdst;
	int sequence_number;
	
	double answer_delay;
	char *protocol_name;
	char *client_id;
	char *user_name;
	double init_time;
	int return_code;
	char *topic;
    int bytes;
	uint16_t message_identifier;
	int number_publish;
	int QoS_publish;
	int id;
	int version_mqtt;

	struct node* next;
}node;


node *hashTable[1000000];
int hashTableSize = 1000000;
int sequence=1;
double first_packet_time_arrival;

int searchNode(int key, uint8_t ipsrc[IP_ALEN], uint8_t ipdst[IP_ALEN], int number_publish, int active, int id){
	node *n;
	key=key%hashTableSize;

	if (active == 1){
		for(n=hashTable[key]; n != NULL; n=n->next){
			if((n->id==id) && ((n->ipsrc[0]==ipsrc[0] && n->ipsrc[1]==ipsrc[1] && n->ipsrc[2]==ipsrc[2] && n->ipsrc[3]==ipsrc[3] && n->ipdst[0]==ipdst[0] && n->ipdst[1]==ipdst[1] && n->ipdst[2]==ipdst[2] && n->ipdst[3]==ipdst[3]) || (n->ipdst[0]==ipsrc[0] && n->ipdst[1]==ipsrc[1] && n->ipdst[2]==ipsrc[2] && n->ipdst[3]==ipsrc[3] && n->ipsrc[0]==ipdst[0] && n->ipsrc[1]==ipdst[1] && n->ipsrc[2]==ipdst[2] && n->ipsrc[3]==ipdst[3]))){   //search if key is same, if it is then search if same "flujo", if not is a colision, go next
				
				n->number_publish=number_publish;
				
				
				return n->sequence_number;
			}
		}

	}else{
		for(n=hashTable[key]; n != NULL; n=n->next){
			if((n->ipsrc[0]==ipsrc[0] && n->ipsrc[1]==ipsrc[1] && n->ipsrc[2]==ipsrc[2] && n->ipsrc[3]==ipsrc[3] && n->ipdst[0]==ipdst[0] && n->ipdst[1]==ipdst[1] && n->ipdst[2]==ipdst[2] && n->ipdst[3]==ipdst[3]) || (n->ipdst[0]==ipsrc[0] && n->ipdst[1]==ipsrc[1] && n->ipdst[2]==ipsrc[2] && n->ipdst[3]==ipsrc[3] && n->ipsrc[0]==ipdst[0] && n->ipsrc[1]==ipdst[1] && n->ipsrc[2]==ipdst[2] && n->ipsrc[3]==ipdst[3])){   //search if key is same, if it is then search if same "flujo", if not is a colision, go next
				first_packet_time_arrival=n->init_time;
				
				return n->sequence_number;
			}
		}
	}
	
	return -1;
}

void insert_IP(int key, uint8_t ipsrc[IP_ALEN], uint8_t ipdst[IP_ALEN], int sequence_number, int Packet_type_mqtt, char *protocol_name, char *client_id, char *user_name, double time_microsec, double first_packet_time, int return_code, char *topic, uint16_t portsrc, uint16_t portdst, int byteLength, uint16_t message_identifier, int number_publish, int QoS_publish, int id, int version_mqtt){
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
	if (Packet_type_mqtt==1){
		new_node->Packet_type_mqtt="CONNECT";
	}
	if (Packet_type_mqtt==2){
		new_node->Packet_type_mqtt="CONNACK";
	}
	if (Packet_type_mqtt==3){
		new_node->Packet_type_mqtt="PUBLISH";
	}
	if (Packet_type_mqtt==4){
		new_node->Packet_type_mqtt="PUBLISH_ACK";
	}
	if (Packet_type_mqtt==5){
		new_node->Packet_type_mqtt="PUBLISH_Received";
	}
	if (Packet_type_mqtt==6){
		new_node->Packet_type_mqtt="PUBLISH_Release";
	}
	if (Packet_type_mqtt==7){
		new_node->Packet_type_mqtt="PUBLISH_Complete";
	}
	if (Packet_type_mqtt==8){
		new_node->Packet_type_mqtt="Subscribe_Req";
	}
	if (Packet_type_mqtt==9){
		new_node->Packet_type_mqtt="Subscribe_ACK";
	}
	if (Packet_type_mqtt==10){
		new_node->Packet_type_mqtt="Unsubscribe_Request";
	}
	if (Packet_type_mqtt==11){
		new_node->Packet_type_mqtt="Unsubscribe_ACK";
	}
	if (Packet_type_mqtt==12){
		new_node->Packet_type_mqtt="PING_Request";
	}
	if (Packet_type_mqtt==13){
		new_node->Packet_type_mqtt="PING_Response";
	}
	if (Packet_type_mqtt==14){
		new_node->Packet_type_mqtt="Disconnect_Req";
	}
	new_node->protocol_name=protocol_name;
	new_node->client_id=client_id;
	new_node->user_name=user_name;
	new_node->init_time=time_microsec;
	new_node->answer_delay=time_microsec-first_packet_time;
	new_node->return_code=return_code;
	new_node->topic=topic;
	new_node->portsrc=portsrc;
    new_node->portdst=portdst;
	new_node->sequence_number=sequence_number;
    new_node->bytes= byteLength;
	new_node->message_identifier=message_identifier;
	new_node->number_publish=number_publish;
	new_node->QoS_publish=QoS_publish;
	new_node->id=id;
	new_node->version_mqtt=version_mqtt;
	
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
int auxialiar=1;
void printlist(node *n,  FILE *f){

	node *n1;
	
	for(n1=n; n1!=NULL; n1=n1->next){
		fprintf(f,"%d;", n1->id);
		
		struct tm  ts;
		char       buf[80];
		const time_t bar = n1->init_time;
    		ts = *localtime((&bar));

		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ts);
		fprintf(f,"%s;", buf);

		fprintf(f,"%s;", n1->Packet_type_mqtt);
		
		fprintf(f,"%d;", n1->sequence_number);

		fprintf(f,"%d.%d.%d.%d;%d.%d.%d.%d;%d;%d;", n1->ipsrc[0], n1->ipsrc[1], n1->ipsrc[2], n1->ipsrc[3], n1->ipdst[0], n1->ipdst[1], n1->ipdst[2], n1->ipdst[3], n1->portsrc, n1->portdst);

		fprintf(f,"%s;", n1->protocol_name);

		fprintf(f,"%s;", n1->client_id);

		fprintf(f,"%s;", n1->user_name);

		if (n1->message_identifier == 0){
			fprintf(f," ;");
		}else{
			fprintf(f,"%d;", n1->message_identifier);
		}

		fprintf(f,"%d;", n1->return_code);
		
		
		fprintf(f,"%s;", n1->topic);
		
		fprintf(f,"%lf;", n1->answer_delay);

        fprintf(f,"%d;", n1->bytes);
		
		fprintf(f,"%d;", n1->number_publish);

		fprintf(f,"%d;", n1->QoS_publish);

		if (n1->version_mqtt == 3){
			fprintf(f,"MQTT v3.1;");	
		}
		if (n1->version_mqtt == 4){
			fprintf(f,"MQTT v3.1.1;");	
		}
		if (n1->version_mqtt == 5){
			fprintf(f,"MQTT v5;");	
		}
		

		fprintf(f,"\n");					
	}
	 
}

void printHashtable( FILE *f){
	fprintf(f,"id;Init_time;Packet_type;Sequence_number;IP_src;IP_dst;Port_src;Port_dst;Protocol_Name;Client_Id;User_Name;Message_identifier;Return_Code;Topic;Answer_delay;Bytes;Number_Publish;QoS_publish;Version\n");
	for(int i=0; i<hashTableSize; i++){
		printlist(hashTable[i], f);
	}
}
/*******************************************************/


int id=0;

void packet_analyzer(const struct pcap_pkthdr *hdr, const uint8_t *pack, int link_layer)
{	
	uint8_t aux8, version_mqtt=0;
	uint16_t prueba1=0,prueba2=0, aux2, aux16=0, portori_tcp, portdes_tcp, keep_alive, message_identifier=0;;
	int protocolo, Total_length, i = 0, hlength, key_IP, hashfind, byteLength, extra=0, ip_tcp_size, number_publish=0, QoS_publish=0, active=0, multiple_mqtt=0, user_name_flag;
	u_int size_ip, size_tcp;
	uint32_t packet_length_mqtt, aux32, aux24;
	
	uint8_t ip_src[IP_ALEN];
	uint8_t ip_dst[IP_ALEN];

	uint8_t Packet_type_mqtt;
	uint8_t return_code = 100;	//this value is like empty, i have to put one so it is initialiced 

	double microseconds, seconds, epochtime;

	microseconds=hdr->ts.tv_usec;
	seconds=hdr->ts.tv_sec;
	epochtime=seconds+microseconds/1000000;
	
	id++;	

	//IP header
	const struct sniff_ip *ip; 
	ip = (struct sniff_ip*)(pack + ETH_HLEN);

	size_ip = IP_HL(ip)*4;

	memcpy(&aux16,&ip->ip_len,sizeof(uint16_t));
	Total_length=ntohs(aux16);
	byteLength=Total_length+ETH_HLEN;
	aux16=0;



	aux2=(ip->ip_off<<4)&0x1;
	memcpy(&prueba1, &aux2, sizeof(uint8_t));

	aux2=ip->ip_off&0xf;
	memcpy(&prueba2, &aux2 , sizeof(uint8_t));
	
	if (prueba1!=0){
		prueba1=255 + prueba2+ prueba1;
	}

	protocolo=ip->ip_p;


	ip_src[0]=ip->ip_src[0];
	for (i = 1; i < IP_ALEN; i++) {
		ip_src[i]=ip->ip_src[i];
	}

	ip_dst[0]=ip->ip_dst[0];
	for (i = 1; i < IP_ALEN; i++) {
		ip_dst[i]=ip->ip_dst[i];
	}
	

	if (prueba2==0){

		///////////////////////////////////////////////////////////////TCP////////////////////////////////////////////////////////////////////
		if (protocolo==6){  //TCP

			const struct sniff_tcp *tcp; /* The TCP header */
			tcp = (struct sniff_tcp*)(pack + ETH_HLEN + size_ip);
			size_tcp = TH_OFF(tcp)*4;

			
			memcpy(&aux16,&tcp->th_sport,sizeof(uint16_t));
			portori_tcp=ntohs(aux16);

			memcpy(&aux16,&tcp->th_dport,sizeof(uint16_t));
			portdes_tcp=ntohs(aux16);
			
			ip_tcp_size=size_ip+size_tcp;

			if (portdes_tcp==1883 || portori_tcp == 1883){ //MQTT
				while(1){
					const struct sniff_mqtt *mqtt;
					mqtt= (struct sniff_mqtt*)(pack + ETH_HLEN + size_ip + size_tcp + multiple_mqtt);

					
					Packet_type_mqtt = ((mqtt->control & 0xf0)>>4);

					QoS_publish = ((mqtt->control & 0x06)>>1);

					/*Length of mqtt portion
					it can have between 1 and 4 bytes.
					Each byte usas 7 bits for the length
					with de MSB use as a continuation flag
					1 continues (rigth) 0 stop*/
					memcpy(&aux8, &mqtt->packet_length , sizeof(uint8_t));				
					if (( aux8 >>7 ) ==1){
							memcpy(&aux16, &mqtt->packet_length , sizeof(uint16_t));

							if (( (aux16 & 0x0080) >>7 ) ==1){
								memcpy(&aux24, &mqtt->packet_length , sizeof(24));

								if (( (aux24 & 0x000080) >>7 ) ==1){
									memcpy(&aux32, &mqtt->packet_length , sizeof(32));
									packet_length_mqtt= (aux32 & 0x7f000000) + (aux32 & 0x007f0000) + (aux32 & 0x00007f00) + (aux32 & 0x0000007f);
									hlength=5;
								}else{
									packet_length_mqtt= (aux24 & 0x7f0000) + (aux24 & 0x007f00) + (aux24 & 0x00007f);
									hlength=4;
								}
								
							}else{
								packet_length_mqtt= (aux16 & 0x7f00) + (aux16 & 0x007f);
								hlength=3;
							}
					}else{
						packet_length_mqtt=aux8 & 0x7F;
						hlength=2;
					}
					multiple_mqtt = packet_length_mqtt + multiple_mqtt + 0x02;
					char *protocol_name="";
					char *client_id="";
					char *user_name="";
					char *topic="";
					
					if (extra==0){
						extra=1;
						
						if (Packet_type_mqtt==1){
							const struct sniff_mqtt_connect_1 *mqtt_connect;
							mqtt_connect= (struct sniff_mqtt_connect_1*)(pack + ETH_HLEN + size_ip + size_tcp + hlength);

							protocol_name = (char *) malloc(mqtt_connect->protocol_name_length);
							strcat(protocol_name, mqtt_connect->protocol_name);
							protocol_name[strlen(protocol_name)-1] = '\0';

							const struct sniff_mqtt_connect_2 *mqtt_connect_2;
							mqtt_connect_2= (struct sniff_mqtt_connect_2*)(pack + ETH_HLEN + size_ip + size_tcp + hlength + ntohs(mqtt_connect->protocol_name_length) + 2); //we add the length of the struct (2 for protocol name length and res por the name)
							
							version_mqtt=mqtt_connect_2->version;
							
							user_name_flag=(mqtt_connect_2->flags && 0x80);
							
							keep_alive=mqtt_connect_2->keep_alive;
							keep_alive=ntohs(keep_alive);

							client_id = (char *) malloc(mqtt_connect_2->client_id_length);
							strcat(client_id, mqtt_connect_2->client_id);
							

							const struct sniff_mqtt_connect_3 *mqtt_connect_3;
							mqtt_connect_3= (struct sniff_mqtt_connect_3*)(pack + ETH_HLEN + size_ip + size_tcp + hlength + ntohs(mqtt_connect->protocol_name_length) + 2 + 6 + ntohs(mqtt_connect_2->client_id_length)); //same metode as earlier 
							
							
							if (user_name_flag == 1){
								user_name = (char *) malloc(mqtt_connect_3->user_name_length);
								strcat(user_name, mqtt_connect_3->user_name);
							}
							

							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 

						}
						if (Packet_type_mqtt==2){

							const struct sniff_mqtt_ack *mqtt_ack;
							mqtt_ack= (struct sniff_mqtt_ack*)(pack + ETH_HLEN + size_ip + size_tcp + hlength);

							return_code=mqtt_ack->return_code;
							
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}
						if (Packet_type_mqtt==3){
							number_publish=1;

							const struct sniff_mqtt_publish *mqtt_publish;
							mqtt_publish= (struct sniff_mqtt_publish*)(pack + ETH_HLEN + size_ip + size_tcp + hlength);

							topic = (char *) malloc((mqtt_publish->topic_length));
							strcat(topic,mqtt_publish->topic);
							
							const struct sniff_mqtt_publish_2 *mqtt_publish_2;
							mqtt_publish_2= (struct sniff_mqtt_publish_2*)(pack + ETH_HLEN + size_ip + size_tcp + hlength + 1 + ntohs(mqtt_publish->topic_length));

							char message[packet_length_mqtt - ntohs(mqtt_publish->topic_length) - 2];
							for(i=0; i<(packet_length_mqtt - ntohs(mqtt_publish->topic_length) - 2); i++){
								message[i]=mqtt_publish_2->message[i];
							}

							topic = strtok(topic, message);   //bug fixer to elimiate part of the topic char that dont understand why is getting in the char 
							
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}
						if (Packet_type_mqtt==4){ //publish ACK
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}
						if (Packet_type_mqtt==5){ //publish received
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}
						if (Packet_type_mqtt==6){ //publish release
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}
						if (Packet_type_mqtt==7){ //publish complete
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}
						if (Packet_type_mqtt==8){
							const struct sniff_mqtt_subscribe_req *mqtt_subscribe;
							mqtt_subscribe= (struct sniff_mqtt_subscribe_req*)(pack + ETH_HLEN + size_ip + size_tcp + hlength);

							message_identifier=ntohs(mqtt_subscribe->message_identifier);

							const struct sniff_mqtt_publish *mqtt_publish;
							mqtt_publish= (struct sniff_mqtt_publish*)(pack + ETH_HLEN + size_ip + size_tcp + hlength +2);
							topic = (char *) malloc((mqtt_publish->topic_length));
							strcat(topic,mqtt_publish->topic);
							
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}

						if (Packet_type_mqtt==9){
							//printf("Msg type mqtt: %d -> Subscribe ACK\n", Packet_type_mqtt);
							const struct sniff_mqtt_subscribe_req *mqtt_subscribe_ack;
							mqtt_subscribe_ack= (struct sniff_mqtt_subscribe_req*)(pack + ETH_HLEN + size_ip + size_tcp + hlength);
							message_identifier=ntohs(mqtt_subscribe_ack->message_identifier);

							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}

						if (Packet_type_mqtt==10){ //Unsubscribe req
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}

						if (Packet_type_mqtt==11){ //Unsubscribe ack
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}

						if (Packet_type_mqtt==12){ //Pinq req
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}

						if (Packet_type_mqtt==12){ //Ping response
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}
						if (Packet_type_mqtt==14){
							key_IP=ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
							if(hashfind == -1){						
								insert_IP(key_IP, ip_src, ip_dst, sequence, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, epochtime, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
								sequence++;
							}else{
								key_IP=hashfind*100000+ip_src[0]+ip_src[1]*10+ip_src[2]+ip_src[3]*100+ip_dst[0]+ip_dst[1]*10+ip_dst[2]+ip_dst[3]*100 + portdes_tcp + portori_tcp - 1883;	//I substract the port that is common to all MQTT packets, not worth it
								insert_IP(key_IP, ip_src, ip_dst, hashfind, Packet_type_mqtt, protocol_name, client_id, user_name, epochtime, first_packet_time_arrival, return_code, topic, portori_tcp, portdes_tcp, byteLength, message_identifier, number_publish, QoS_publish,  id, version_mqtt);
							} 
						}
					}

					//To check multiple publish messages per packet
					if ((ip_tcp_size + packet_length_mqtt + 0x02)>=Total_length){
						extra=0;
						return;
					}else{
						ip_tcp_size=ip_tcp_size + packet_length_mqtt + 0x02;
						if (Packet_type_mqtt==3){
							active=1;
							number_publish++;	
							hashfind=searchNode(key_IP, ip_src, ip_dst, number_publish, active, id);
						}
						
						
					}
					
				}
				
							

			}

		}
	}
}


int main(int argc, char **argv){
	uint8_t *pack = NULL;
	struct pcap_pkthdr *hdr;
	char errbuf[PCAP_ERRBUF_SIZE];
	char entrada[256];		//archivo pcap que queremos leer
	u_int precision=PCAP_TSTAMP_PRECISION_MICRO; //PCAP_TSTAMP_PRECISION_NANO nanoseconds in case of necesity
	int long_index = 0, retorno = 0, link_layer;
	char opt;		
	//REGISTRO
	FILE *f = fopen("registerMQTT.csv","w");
	//Comprobamos que se le pasa un archivo, si no ocurre se para la ejecución y se muestra como hacerlo
	if (argc > 1) {
		if (strlen(argv[1]) < 256) {
			strcpy(entrada, argv[1]);
		}

	} else {
		//printf("Ejecucion: %s <-f traza.pcap \n", argv[0]);
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
					//printf("Ha seleccionado más de una fuente de datos\n");
					pcap_close(descr);
					exit(ERROR);
				}
				
				if ((descr = pcap_open_offline_with_tstamp_precision(optarg, precision, errbuf)) == NULL) {
					//printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
					exit(ERROR);
				}

				break;

			
			case '?' :
			default:
				//printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
				break;
		}
	}

	if (!descr) {
		//printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}


	link_layer=pcap_datalink(descr);	//returns the link-layer header type for the live capture 
	
	
	//const struct pcap_file_header* myStruct;
	//myStruct= (struct pcap_file_header*)(pack);

	do{
		retorno = pcap_next_ex(descr, &hdr, (const u_char **)&pack);
		if (retorno == PACK_READ) { //Todo correcto
			packet_analyzer(hdr, pack, link_layer);
			////printf("%d\n", myStruct->linktype);				
		}

	} while (retorno != TRACE_END);

	printHashtable(f);


	return OK;
}
