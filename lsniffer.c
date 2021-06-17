
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<time.h>
 
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   
#include<netinet/udp.h>   
#include<netinet/tcp.h>  
#include<netinet/ip.h>    
 
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
void no_tcp_data(void);
void no_udp_data(void);
void no_icmp_data(void);
void day_and_time(void);
int file_count=67; 
FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,total=0,i,j; 
int main()
{
    pcap_if_t *alldevsp , *device;
    pcap_t *handle; 
    char errbuf[100] , *devname , devs[100][100];
    int count = 1 , n;
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done");
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n);
    devname = devs[n];
    printf("Opening device %s for sniffing ... " , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    printf("Done\n");
    char file_name[32];
     while(file_count!=0)
     {
    snprintf(file_name,sizeof(char)*32,"%i.csv",file_count);
    logfile=fopen(file_name,"w");
    
    if(logfile==NULL) 
    {
        printf("Unable to create file.");
    }
    pcap_loop(handle , 200, process_packet , NULL);
    ++file_count;
    sleep(200);
    
    
    }
   return 0;   
}
 
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch (iph->protocol) 
    {
        case 1:  
            ++icmp;
            print_icmp_packet( buffer , size);
            ++total;
            break;
        case 6:  
            ++tcp;
            print_tcp_packet(buffer , size);
            ++total;
            break;
        case 17: 
            ++udp;
            print_udp_packet(buffer , size);
            ++total;
            break;
        default: 
            ++others;
            ++total;
            print_ip_header(buffer,size);
            no_tcp_data();
            no_udp_data();
            no_icmp_data();
            day_and_time();
            
           break;
    }
    

  printf("TCP : %d   UDP : %d   ICMP : %d  others :%d total : %d \r", tcp , udp , icmp , others ,total);
    
}    
    
 
void print_ethernet_header(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer; 
    fprintf(logfile , "\n");
    fprintf(logfile , "    %.2X-%.2X-%.2X-%.2X-%.2X-%.2X,%.2X-%.2X-%.2X-%.2X-%.2X-%.2X  ", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] ,eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
    
}
 
void print_ip_header(const u_char * Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    fprintf(logfile , "    ,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s",(unsigned int)iph->version,(unsigned int)(iph->ihl)*4,(unsigned int)iph->tos,ntohs(iph->tot_len),ntohs(iph->id),(unsigned int)iph->ttl,(unsigned int)iph->protocol,ntohs(iph->check),inet_ntoa(source.sin_addr),inet_ntoa(dest.sin_addr));
    }
    
 
void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    print_ip_header(Buffer,Size);
    fprintf(logfile , "  ,%u,%u,%u,%u,%d,%d,%d,%d,%d,%d,%d,%d,%d,",ntohs(tcph->source),ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq),(unsigned int)tcph->urg,(unsigned int)tcph->ack,(unsigned int)tcph->psh,(unsigned int)tcph->rst,(unsigned int)tcph->syn,(unsigned int)tcph->fin,ntohs(tcph->window),ntohs(tcph->check),tcph->urg_ptr);
    no_udp_data();
    no_icmp_data();
    day_and_time();
}
 
void print_udp_packet(const u_char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    print_ip_header(Buffer,Size); 
    no_tcp_data(); 
    fprintf(logfile , "%d,%d,%d,%d," , ntohs(udph->source),ntohs(udph->dest),ntohs(udph->len),ntohs(udph->check));
    no_icmp_data();  
    day_and_time();
    }
 
void print_icmp_packet(const u_char * Buffer , int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
    print_ip_header(Buffer , Size);
    no_tcp_data();
    no_udp_data();
    fprintf(logfile , " %d,%d,%d",(unsigned int)(icmph->type),(unsigned int)(icmph->code),ntohs(icmph->checksum));
    day_and_time();
}
 void no_tcp_data(void)
{

int tcp_data=0;
fprintf(logfile,",%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,",tcp_data,tcp_data,tcp_data,tcp_data,tcp_data,tcp_data,tcp_data,tcp_data,tcp_data,tcp_data,tcp_data,tcp_data,tcp_data);
}
void no_icmp_data(void)
{
int data1=0,data2=0,data3=0;
fprintf(logfile,"%d,%d,%d",data1,data2,data3);
}
void no_udp_data(void)
{
int udp_data=0;
fprintf(logfile,"%d,%d,%d,%d,",udp_data,udp_data,udp_data,udp_data);
}
void day_and_time(void)
{
  time_t t = time(NULL);
  struct tm tm = *localtime(&t);
  fprintf(logfile,",%02d,%02d",  tm.tm_hour, tm.tm_min );
}
  
