#include <pcap.h>
#include <QTextStream>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <cstring>

#define MY_NTOHS(n) ((uint16_t)((n & 0x00ff) << 8 | (n & 0xff00) >> 8))
#define MY_NTOHL(n) ((uint16_t)((n & 0x000000ff) << 24 | (n & 0x0000ff00) << 8 | (n & 0x00ff0000) >> 8 | (n & 0xff000000) >> 24))

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

#define IP_HDR(pkt) ((struct ip_hdr*)((unsigned char*)pkt + sizeof(struct eth_hdr)))
#define TCP_HDR_HLEN(hdr) ((MY_NTOHS((hdr)->hlen_with_flags) & 0b1111000000000000) >> 4)
#define TCP_HDR_FLAGS(hdr) (MY_NTOHS((hdr)->hlen_with_flags) & 0b0000111111111111)
#define TCP_HDR(pkt) ((struct tcp_hdr*)((unsigned char*)IP_HDR(pkt) + ip_hdr->hlen * 4))
#define TCP_PAYLOAD(pkt) ((char*)((unsigned char*)TCP_HDR(pkt) + MY_NTOHS(TCP_HDR_HLEN(TCP_HDR(pkt))) * 4))
#define TCP_PAYLOAD_LEN(pkt) (MY_NTOHS(IP_HDR(pkt)->tlen) - (IP_HDR(pkt)->hlen + MY_NTOHS(TCP_HDR_HLEN(TCP_HDR(pkt)))) * 4)

void print_eth_hdr(const struct eth_hdr* hdr) {
  std::printf("eth dmac %02x:%02x:%02x:%02x:%02x:%02x\n", hdr->dmac[0], hdr->dmac[1], hdr->dmac[2], hdr->dmac[3], hdr->dmac[4], hdr->dmac[5]);
  std::printf("eth smac %02x:%02x:%02x:%02x:%02x:%02x\n", hdr->smac[0], hdr->smac[1], hdr->smac[2], hdr->smac[3], hdr->smac[4], hdr->smac[5]);
  std::printf("eth type 0x%04x\n", MY_NTOHS(hdr->type));
}

void print_ip_hdr(const struct ip_hdr* hdr) {
  std::printf("ip ver %u\n", hdr->ver);
  std::printf("ip hlen %u\n", hdr->hlen);
  std::printf("ip type of service 0x%x\n", hdr->tos);
  std::printf("ip tlen %d=0x%x(0x%x)\n", MY_NTOHS(hdr->tlen), MY_NTOHS(hdr->tlen), hdr->tlen);
  std::printf("ip id 0x%x(0x%x)\n", MY_NTOHS(hdr->id), hdr->id);
  std::printf("ip flags 0x%x\n", MY_NTOHS(hdr->flags));
  std::printf("ip ttl %u\n", hdr->ttl);
  std::printf("ip proto 0x%x\n", hdr->proto);
  std::printf("ip chksum 0x%x\n", MY_NTOHS(hdr->chksum));
  std::printf("ip src %d.%d.%d.%d\n", hdr->sip[0], hdr->sip[1], hdr->sip[2], hdr->sip[3]);
  std::printf("ip dst %d.%d.%d.%d\n", hdr->dip[0], hdr->dip[1], hdr->dip[2], hdr->dip[3]);
}

void print_tcp_hdr(const struct tcp_hdr* hdr) {
  std::printf("tcp sport: %u\n", MY_NTOHS(hdr->sport));
  std::printf("tcp dport: %u\n", MY_NTOHS(hdr->dport));
  std::printf("tcp seq: %x\n", MY_NTOHL(hdr->seq_num));
  std::printf("tcp ack: %x\n", MY_NTOHL(hdr->ack_num));
  std::printf("tcp hlen_with_flags 0x%x\n", hdr->hlen_with_flags);
  std::printf("tcp hlen: 0x%x\n", MY_NTOHS(TCP_HDR_HLEN(hdr)));
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
    struct pcap_pkthdr* pkt_info;
    const u_char* pkt;
    int res = pcap_next_ex(handle, &pkt_info, &pkt);
    if(res == 0)
      continue;
    if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
      break;
    const struct eth_hdr* eth_hdr = (struct eth_hdr*)pkt;
    if(MY_NTOHS(eth_hdr->type) == 0x0800) {
      const struct ip_hdr* ip_hdr = IP_HDR(pkt);
      if(ip_hdr->proto == 0x06) {
        const struct tcp_hdr* tcp_hdr = TCP_HDR(pkt);
        if(TCP_HDR_FLAGS(tcp_hdr) == 0x018 && (MY_NTOHS(tcp_hdr->dport) == 80 || MY_NTOHS(tcp_hdr->sport) == 80)) {
          print_eth_hdr(eth_hdr);
          print_ip_hdr(ip_hdr);
          print_tcp_hdr(tcp_hdr);

          uint16_t body_len = TCP_PAYLOAD_LEN(pkt);
          for(uint16_t i = 0; i != body_len; ++i) {
            std::printf("%c", *(TCP_PAYLOAD(pkt) + i));
          }
          std::printf("\n----------------------------------\n");
        }
      }
    }
    //std::printf("%08x\n", dmac);
    //QTextStream(stdout) << pkt_info->caplen << endl;
    //QTextStream(stdout) << std::strlen((char*)pkt) << endl;
    //QTextStream(stdout) << pkt << endl;
  }
  pcap_close(handle);
}
