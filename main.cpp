#include <pcap.h>
#include <QTextStream>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <cstring>

uint16_t my_ntohs(uint16_t n) {
  return (n & 0x00ff) << 8 | (n & 0xff00) >> 8;
}

uint32_t my_ntohl(uint32_t n) {
  return (n & 0x000000ff) << 24 | (n & 0x0000ff00) << 8 | (n & 0x00ff0000) >> 8 | (n & 0xff000000) >> 24;
}

struct eth_hdr {
  uint8_t dmac[6];
  uint8_t smac[6];
  uint16_t type;
} __attribute__((packed));

struct ip_hdr {
  unsigned char hlen:4;
  unsigned char ver:4;
  uint8_t tos;
  uint16_t tlen;
  uint16_t id;

  uint16_t flags;

  uint8_t ttl;
  uint8_t proto;
  uint16_t chksum;
  uint8_t sip[4];
  uint8_t dip[4];
} __attribute__((packed));


struct tcp_hdr {
  uint16_t sport;
  uint16_t dport;
  uint32_t seq_num;
  uint32_t ack_num;
  uint16_t hlen_with_flags;
  uint16_t wsize;
  uint16_t chksum;
  uint16_t urg_ptr;
  uint8_t options[8];
} __attribute__((packed));

#define IP_HDR_START(pkt) (struct ip_hdr*)((unsigned char*)pkt + sizeof(struct eth_hdr))
#define TCP_HDR_HLEN(hdr) my_ntohs((my_ntohs((hdr)->hlen_with_flags) & 0b1111000000000000) >> 4)
#define TCP_HDR_FLAGS(hdr) (my_ntohs((hdr)->hlen_with_flags) & 0b0000111111111111)
#define TCP_HDR_START(pkt) (struct tcp_hdr*)((unsigned char*)IP_HDR_START(pkt) + ip_hdr->hlen * 4)
#define TCP_HDR_END(pkt) (char*)((unsigned char*)TCP_HDR_START(pkt) + TCP_HDR_HLEN(TCP_HDR_START(pkt)) * 4)

void print_eth_hdr(const struct eth_hdr* hdr) {
  std::printf("eth dmac %02x:%02x:%02x:%02x:%02x:%02x\n", hdr->dmac[0], hdr->dmac[1], hdr->dmac[2], hdr->dmac[3], hdr->dmac[4], hdr->dmac[5]);
  std::printf("eth smac %02x:%02x:%02x:%02x:%02x:%02x\n", hdr->smac[0], hdr->smac[1], hdr->smac[2], hdr->smac[3], hdr->smac[4], hdr->smac[5]);
  std::printf("eth type 0x%04x\n", my_ntohs(hdr->type));
}

void print_ip_hdr(const struct ip_hdr* hdr) {
  std::printf("ip ver %u\n", hdr->ver);
  std::printf("ip hlen %u\n", hdr->hlen);
  std::printf("ip type of service 0x%x\n", hdr->tos);
  std::printf("ip tlen %d=0x%x(0x%x)\n", my_ntohs(hdr->tlen), my_ntohs(hdr->tlen), hdr->tlen);
  std::printf("ip id 0x%x(0x%x)\n", my_ntohs(hdr->id), hdr->id);
  std::printf("ip flags 0x%x\n", my_ntohs(hdr->flags));
  std::printf("ip ttl %u\n", hdr->ttl);
  std::printf("ip proto 0x%x\n", hdr->proto);
  std::printf("ip chksum 0x%x\n", my_ntohs(hdr->chksum));
  std::printf("ip src %d.%d.%d.%d\n", hdr->sip[0], hdr->sip[1], hdr->sip[2], hdr->sip[3]);
  std::printf("ip dst %d.%d.%d.%d\n", hdr->dip[0], hdr->dip[1], hdr->dip[2], hdr->dip[3]);
}

void print_tcp_hdr(const struct tcp_hdr* hdr) {
  std::printf("tcp sport: %u\n", my_ntohs(hdr->sport));
  std::printf("tcp dport: %u\n", my_ntohs(hdr->dport));
  std::printf("tcp seq: %x\n", my_ntohl(hdr->seq_num));
  std::printf("tcp ack: %x\n", my_ntohl(hdr->ack_num));
  std::printf("tcp hlen_with_flags 0x%x\n", hdr->hlen_with_flags);
  std::printf("tcp hlen: 0x%x\n", TCP_HDR_HLEN(hdr));
  std::printf("tcp flags: 0x%x\n", TCP_HDR_FLAGS(hdr));
  std::printf("tcp wsize: 0x%x\n", hdr->wsize);
  std::printf("tcp chksum: 0x%x\n", hdr->chksum);
  std::printf("tcp urg_ptr: 0x%x\n", hdr->urg_ptr);
}

int main(int argc, char** argv) {
  /*
  QGuiApplication app{argc, argv};
  QQmlApplicationEngine engine;
  const QUrl url{QStringLiteral("qrc:/main.qml")};
  QObject::connect(&engine, &QQmlApplicationEngine::objectCreated,
                   &app, [url](QObject *obj, const QUrl &objUrl) {
    if(!obj && url == objUrl)
      QCoreApplication::exit(-1);
  }, Qt::QueuedConnection);

  engine.load(url);

  return app.exec();
  */
  char errbuf[PCAP_ERRBUF_SIZE];
  if(argc >= 2)
    QTextStream(stdout) << "Hello World! " << argv[1] << endl;

  pcap_if_t* alldevsp;
  pcap_findalldevs(&alldevsp, errbuf);
  if(alldevsp != NULL) {
    for(pcap_if_t* curdevp = alldevsp; curdevp->next != NULL; curdevp = curdevp->next) { QTextStream(stdout) << curdevp->name << endl;
    }
  }
  
  pcap_t* handle = pcap_open_live("docker0", BUFSIZ, 1, 1000, errbuf);
  if(handle == NULL) {
    QTextStream(stdout) << errbuf << endl;
    return -1;
  }

  while(true) {
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    int res = pcap_next_ex(handle, &pkt_header, &pkt_data);
    if(res == 0)
      continue;
    if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
      break;
    const struct eth_hdr* eth_hdr = (struct eth_hdr*)pkt_data;
    if(my_ntohs(eth_hdr->type) == 0x0800) {
      const struct ip_hdr* ip_hdr = IP_HDR_START(pkt_data);
      if(ip_hdr->proto == 0x06) {
        const struct tcp_hdr* tcp_hdr = TCP_HDR_START(pkt_data);
        if(TCP_HDR_FLAGS(tcp_hdr) == 0x018 && (my_ntohs(tcp_hdr->dport) == 80 || my_ntohs(tcp_hdr->sport) == 80)) {
          print_eth_hdr(eth_hdr);
          print_ip_hdr(ip_hdr);
          print_tcp_hdr(tcp_hdr);

          uint16_t body_len = my_ntohs(ip_hdr->tlen) - (ip_hdr->hlen + TCP_HDR_HLEN(tcp_hdr)) * 4;
          std::printf("body len: %d = ip tlen %d - (ip hlen %d + tcp hlen 0x%x(%d)) * 4\n", body_len, my_ntohs(ip_hdr->tlen), ip_hdr->hlen, TCP_HDR_HLEN(tcp_hdr), TCP_HDR_HLEN(tcp_hdr));
      
          for(uint16_t i = 0; i != body_len; ++i) {
            std::printf("%c", *(TCP_HDR_END(pkt_data) + i));
          }
          std::printf("\n----------------------------------\n");
        }
      }
    }
    //std::printf("%08x\n", dmac);
    //QTextStream(stdout) << pkt_header->caplen << endl;
    //QTextStream(stdout) << std::strlen((char*)pkt_data) << endl;
    //QTextStream(stdout) << pkt_data << endl;
  }
  pcap_close(handle);
}
