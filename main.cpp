#include <stdio.h>
#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <algorithm>
#include <math.h>
using namespace std;
#define ethsize 6
#define MAX_PTRN 1024
uint8_t pattern[MAX_PTRN] = {};
uint8_t mac_address_mine[6];
int packet_type;//0 --> http, 1 --> https
int pattern_length, fail[MAX_PTRN];
struct MY_TCP_Header{
    struct libnet_ethernet_hdr ether_hdr;
    struct libnet_ipv4_hdr ip_hdr;
    struct libnet_tcp_hdr tcp_hdr;
    string tcp_data;
    uint32_t get_my_tcp_header_length(){
        return sizeof(ether_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr) + tcp_data.size();
    }
};
void copy_and_send(MY_TCP_Header *mypacket, pcap_t *handle){
    uint32_t send_packet_length = mypacket->get_my_tcp_header_length();
    uint8_t * send_packet = (uint8_t *)malloc(send_packet_length);

    int ip_hdr_offset = sizeof(mypacket->ether_hdr);
    int tcp_hdr_offset = ip_hdr_offset + sizeof(mypacket->ip_hdr);


    memcpy(&(send_packet[0]), &(mypacket->ether_hdr), sizeof(mypacket->ether_hdr));
    memcpy(&(send_packet[ip_hdr_offset]), &(mypacket->ip_hdr), sizeof(mypacket->ip_hdr));
    memcpy(&(send_packet[tcp_hdr_offset]), &(mypacket->tcp_hdr), sizeof(mypacket->tcp_hdr));
    if(!(mypacket->tcp_data.empty())){
        int tcp_data_offset = tcp_hdr_offset + sizeof(mypacket->tcp_hdr);
        memcpy(&(send_packet[tcp_data_offset]), mypacket->tcp_data.c_str(), mypacket->tcp_data.size());
    }
    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&send_packet[0]), send_packet_length);
    //free(send_packet);
}
MY_TCP_Header forward_RST, backward_FIN_RST;
int setting_my_mac(){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
        /* handle error*/
        return 0;
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        /* handle error */
        return 0;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else {
            /* handle error */
            return 0;
        }
    }
    if (success){
        unsigned char mac_address[6];
        memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
        int i;
        printf("My mac address : [");
        for(i=0;i<ETHER_ADDR_LEN;i++){
            if(i!=0){
                printf(":");
            }
            mac_address_mine[i]=static_cast<uint8_t>(mac_address[i]);
            printf("%02x",(u_int8_t)mac_address_mine[i]);
        }
        printf("]\n");
    }
    return success;
}

void usage() {
    printf("syntax : tcp_block <interface> <host>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}
void set_fail(){
    //https://www.acmicpc.net/problem/1786
    //kmp fail function
    fail[0] = -1;
    for (int i = 1, j = 0; i < pattern_length; i++, j++) {
        while (j > 0 && pattern[i] != pattern[j]) {
            j = fail[j - 1] + 1;
        }
        if (pattern[i] != pattern[j]) {
            j = -1;
        }
        fail[i] = j;
    }
}

int find_pattern(uint8_t *packet_output, int packet_length){
    //https://www.acmicpc.net/problem/1786
    int ans=0;
    if(packet_length == 0){
        return 0;
    }
    for (int i = 0, j = 0; i < packet_length; i++, j++) {
        while (j > 0 && packet_output[i] != pattern[j]) {
            j = fail[j - 1] + 1;
        }
        if (packet_output[i] == pattern[j]) {
            if (j == pattern_length - 1) {
                ans=1;
                break;
            }
        }
        else {
            j = -1;
        }
    }
    return ans;
}
void set_eth_header(libnet_ethernet_hdr* packet_eth){
    int i;
    for(i=0;i<6;i++){
        //smac : L2 switch의 CAM table이 깨지는 것을 방지하기 위해 자신 인터페이스의 mac 값을 사용한다.
        forward_RST.ether_hdr.ether_shost[i]=mac_address_mine[i];
        backward_FIN_RST.ether_hdr.ether_shost[i]=mac_address_mine[i];
    }
    for(i=0;i<6;i++){
        //dmac : Forward의 경우 org-packet의 ether.dmac
        //dmac : Backward의 경우 org-packet의 ether.smac 값을 사용한다.
        forward_RST.ether_hdr.ether_dhost[i]=packet_eth->ether_dhost[i];
        backward_FIN_RST.ether_hdr.ether_dhost[i]=packet_eth->ether_shost[i];
    }
    forward_RST.ether_hdr.ether_type=htons(ETHERTYPE_IP);
    backward_FIN_RST.ether_hdr.ether_type=htons(ETHERTYPE_IP);
    //set as ipv4
}
void set_ip_header_without_add_FIN(libnet_ipv4_hdr* packet_ip){

    forward_RST.ip_hdr.ip_hl=0x05;
    backward_FIN_RST.ip_hdr.ip_hl=0x05;

    forward_RST.ip_hdr.ip_v=0x04;
    backward_FIN_RST.ip_hdr.ip_v=0x04;

    forward_RST.ip_hdr.ip_tos = 0x00;
    backward_FIN_RST.ip_hdr.ip_tos = 0x00;

    //len : sizeof(IP) + sizeof(TCP) 값으로 설정하면 된다. FIN message가 존재하는 경우 메시지의 크기만큼 더해준다.
    forward_RST.ip_hdr.ip_len = htons(20 + 20);
    backward_FIN_RST.ip_hdr.ip_len = htons(20 + 20);//not calculated! if backward_FIN

    forward_RST.ip_hdr.ip_id = 0x00;
    backward_FIN_RST.ip_hdr.ip_id = 0x00;

    forward_RST.ip_hdr.ip_off = 0x00;
    backward_FIN_RST.ip_hdr.ip_off = 0x00;

    forward_RST.ip_hdr.ip_ttl = packet_ip->ip_ttl;
    backward_FIN_RST.ip_hdr.ip_ttl = 128;

    forward_RST.ip_hdr.ip_p = IPPROTO_TCP;
    backward_FIN_RST.ip_hdr.ip_p = IPPROTO_TCP;

    forward_RST.ip_hdr.ip_sum = 0;//not calculated!
    backward_FIN_RST.ip_hdr.ip_sum = 0;//not calculated!

    //sip, dip : Forward의 경우 org-packet의 값을 그대로 사용하면 되고
    forward_RST.ip_hdr.ip_src = packet_ip->ip_src;
    forward_RST.ip_hdr.ip_dst = packet_ip->ip_dst;

    //sip, dip : Backward의 경우 org-packet의 값을 바꿔서 설정한다.
    backward_FIN_RST.ip_hdr.ip_src = packet_ip->ip_dst;
    backward_FIN_RST.ip_hdr.ip_dst = packet_ip->ip_src;
}
void set_tcp_header(libnet_tcp_hdr* packet_tcp, uint32_t org_data_len){ // set ip header length too!
    //checksum to 0
    forward_RST.tcp_hdr.th_sum = 0;
    backward_FIN_RST.tcp_hdr.th_sum = 0;

    //sport, dport : Forward의 경우 org-packet의 값을 그대로 사용하면 되고
    forward_RST.tcp_hdr.th_sport = packet_tcp->th_sport;
    forward_RST.tcp_hdr.th_dport = packet_tcp->th_dport;
    //sport, dport : Backward의 경우 org-packet의 값을 바꿔서 설정한다.
    backward_FIN_RST.tcp_hdr.th_sport = packet_tcp->th_dport;
    backward_FIN_RST.tcp_hdr.th_dport = packet_tcp->th_sport;

    // default tcp header len : 5
    forward_RST.tcp_hdr.th_off = 0x05;
    backward_FIN_RST.tcp_hdr.th_off = 0x05;

    // window size uint16_t th_win;
    forward_RST.tcp_hdr.th_win = htons(0xd431);
    backward_FIN_RST.tcp_hdr.th_win = htons(0xd431);

    //seq : org-packet.seq 값에 org-packet.tcp_data_size(org_data_len) 를 더한 값.
    //uint32_t th_seq;          /* sequence number */ --> htonl
    forward_RST.tcp_hdr.th_seq = htonl(ntohl(packet_tcp->th_seq)+org_data_len);
    backward_FIN_RST.tcp_hdr.th_seq = htonl(ntohl(packet_tcp->th_seq)+org_data_len);

    //ack : org-packet.ack 값 그대로. Backward의 경우 seq와 ack 값을 바꾸어서 설정한다.
    forward_RST.tcp_hdr.th_ack = packet_tcp->th_ack;
    backward_FIN_RST.tcp_hdr.th_ack = packet_tcp->th_ack;

    swap(backward_FIN_RST.tcp_hdr.th_seq, backward_FIN_RST.tcp_hdr.th_ack);


    //flag : RST flag나 FIN flags를 set해 준다. SYN flag는 reset, ACK flag는 set해 준다.
    forward_RST.tcp_hdr.th_flags = 0;
    backward_FIN_RST.tcp_hdr.th_flags = 0;
    forward_RST.tcp_hdr.th_flags = TH_ACK;
    backward_FIN_RST.tcp_hdr.th_flags = TH_ACK;

    forward_RST.tcp_data.clear();
    backward_FIN_RST.tcp_data.clear();

    //forward RST
    forward_RST.tcp_hdr.th_flags = TH_RST;

    if(packet_type == 0){//http, Backward FIN
        backward_FIN_RST.tcp_hdr.th_flags |= TH_FIN;
        backward_FIN_RST.tcp_data = "blocked!!!";
        // + set ip header length!, add tcp_data's length!
        backward_FIN_RST.ip_hdr.ip_len = htons(ntohs(backward_FIN_RST.ip_hdr.ip_len) + backward_FIN_RST.tcp_data.length());
    }
    else{//https, Backward RST
        backward_FIN_RST.tcp_hdr.th_flags = TH_RST;
        backward_FIN_RST.tcp_data.clear();
    }
}
uint32_t ip_checksum_add(uint32_t current, const void* data, int len) {
    uint32_t checksum = current;
    uint16_t* data_16 = (uint16_t*) data;
    for(int i=0;i<(len/2);i++){
        checksum = checksum + ntohs(data_16[i]);
        if(checksum & (0x10000)){
            checksum = (checksum & (0xffff)) + 1;
        }
    }
    return checksum;
}
void set_checksum_ip_tcp_header(MY_TCP_Header *chk_set_tcp_hdr){
    chk_set_tcp_hdr->ip_hdr.ip_sum = ~htons(ip_checksum_add((uint32_t)0, &(chk_set_tcp_hdr->ip_hdr), 20));
    uint16_t pseudo_header[6];
    memcpy(&(pseudo_header[0]), &chk_set_tcp_hdr->ip_hdr.ip_src, 4);
    //ip header's source ip
    memcpy(&(pseudo_header[2]), &chk_set_tcp_hdr->ip_hdr.ip_dst, 4);
    //ip header's destination ip
    pseudo_header[4] = htons(IPPROTO_TCP);
    //zero byte + protocol type(IPPROTO_TCP, 6)
    pseudo_header[5] = htons(ntohs(chk_set_tcp_hdr->ip_hdr.ip_len) - chk_set_tcp_hdr->ip_hdr.ip_hl * 4);
    //TCP 헤더 + DATA의 총 길이(바이트)
    //chk_set_tcp_hdr->ip_hdr.ip_len : ip header + tcp header + tcp data
    //chk_set_tcp_hdr->ip_hdr.ip_hl*4: ip header(20)
    uint32_t imsi_sum = 0;
    imsi_sum = ip_checksum_add(imsi_sum, &pseudo_header, 12);
    //pseudo_header checksum
    imsi_sum = ip_checksum_add(imsi_sum, &(chk_set_tcp_hdr->tcp_hdr), 20);
    //tcp header checksum
    if(!(chk_set_tcp_hdr->tcp_data.empty())){
        imsi_sum = ip_checksum_add(imsi_sum,
                                   chk_set_tcp_hdr->tcp_data.c_str(),
                                   chk_set_tcp_hdr->tcp_data.size());
        //https://stackoverflow.com/questions/905479/stdstring-length-and-size-member-functions
        //same meaning : length, size
        //tcp data checksum if exist(in the case of backward_FIN, "blocked!!!")
    }
    chk_set_tcp_hdr->tcp_hdr.th_sum = ~htons(imsi_sum);
}

void print_eth_host_dest(int type, u_int8_t ethhost[ethsize]){
    if(type==1){
        printf("Dst");
    }
    else{
        printf("Src");
    }
    printf(" mac address : [");
    int i;
    for(i=0;i<ethsize;i++){
        if(i!=0){
            printf(":");
        }
        printf("%02x",(u_int8_t)ethhost[i]);
    }
    printf("]\n");
}

void print_Ethernet_Header(struct libnet_ethernet_hdr* packet_eth){
    printf("--------------Ethernet Header--------------\n");
    print_eth_host_dest(0, packet_eth->ether_shost);
    print_eth_host_dest(1, packet_eth->ether_dhost);
    //16bit, network byte order --> host byte order chanded at main
    printf("Ethertype : %04x\n",packet_eth->ether_type);
}

int main(int argc, char *argv[]){
    if (argc != 3) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s! - %s\n", dev, errbuf);
        return -1;
    }
    int errmy=setting_my_mac();
    if(errmy==0){
        printf("Handle error on finding my mac address\n");
        return 3;
    }
    pattern_length = strlen(argv[2]);
    memcpy(pattern, argv[2], strlen(argv[2]));
    set_fail();
    while(true){
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0){
            continue;
        }
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        //packet analyze
        struct libnet_ethernet_hdr* packet_eth=(struct libnet_ethernet_hdr *)(packet);
        packet_eth->ether_type=ntohs(packet_eth->ether_type);
        if(packet_eth->ether_type != ETHERTYPE_IP){//ipv4 use X
           continue;
        }
        int eth_header_size=(int)sizeof(struct libnet_ethernet_hdr);
        struct libnet_ipv4_hdr *packet_ip=(struct libnet_ipv4_hdr *)(packet + eth_header_size);
        if(packet_ip->ip_p != IPPROTO_TCP){//protocol isn't tcp
           continue;
        }
        int total_packet_length=(int)ntohs(packet_ip->ip_len);
        int ip_header_length = ((int)packet_ip->ip_hl)*4;
        int tcp_header_offset = ip_header_length + eth_header_size;//word --> byte, * 4
        struct libnet_tcp_hdr *packet_tcp=(struct libnet_tcp_hdr *)(packet + tcp_header_offset);
        int tcp_header_length = ((int)packet_tcp->th_off)*4;
        int packet_data_offset=tcp_header_offset+tcp_header_length;
        uint8_t * packet_output=(uint8_t *)(packet + packet_data_offset);
        int packet_length=total_packet_length-ip_header_length-tcp_header_length;
        /*
        int dest_port = htons(packet_tcp->th_dport);
        if(dest_port != 80 && dest_port != 443){
            continue;
        }
        if(dest_port == 80){//http
            packet_type = 0;
        }
        if(dest_port == 443){//https
            packet_type = 1;
        }
        */
        packet_type = 0;
        if(find_pattern(packet_output, packet_length)==0){//not matched!
            continue;
        }
        /*
        printf("packet type : %d\n", packet_type);
        printf("%u bytes captured\n", header->caplen);
        printf("IP version : %#02x\n", packet_ip->ip_v);
        printf("IP protocol : %#02x\n", packet_ip->ip_p);
        printf("IP header length : %#02x\n", packet_ip->ip_hl << 2);
        printf("IP header, total packet length : %d\n", total_packet_length);
        print_Ethernet_Header(packet_eth);
        printf("Src ip : %s \n",inet_ntoa(packet_ip->ip_src));
        printf("Dst ip : %s \n",inet_ntoa(packet_ip->ip_dst));
        printf("--------------TCP Header--------------\n");
        printf("Src port : %d\n", (int)ntohs(packet_tcp->th_sport));
        printf("Dst port : %d\n", (int)ntohs(packet_tcp->th_dport));
        printf("Seq numb of original packet : %u\n", ntohl(packet_tcp->th_seq));
        printf("Seq numb of original packet : %u\n", ntohl(packet_tcp->th_seq));
        */
        forward_RST.tcp_data.clear();
        backward_FIN_RST.tcp_data.clear();
        //Ethernet header
        set_eth_header(packet_eth);
        set_ip_header_without_add_FIN(packet_ip);
        set_tcp_header(packet_tcp, (uint32_t)packet_length);
        set_checksum_ip_tcp_header(&forward_RST);
        set_checksum_ip_tcp_header(&backward_FIN_RST);
        copy_and_send(&forward_RST,handle);
        copy_and_send(&backward_FIN_RST,handle);
        printf("I catched!\n");
    }
    pcap_close(handle);
}
