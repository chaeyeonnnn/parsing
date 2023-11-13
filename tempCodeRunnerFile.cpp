#include <pcap.h>
#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <iomanip> 
using namespace std;
#pragma pack(push, 1)


// pcap --> HTTP 뽑는 법!
// 1. 이더넷 프레임에서 이더넷 타입을 보고 IP 패킷 뽑기
// 2. IP 헤더의 프로토콜 필드 확인
// 3. 프로토콜 번호 6이면 TCP
// 4. TCP 헤더에서 목적지/출발지 포트 80이면 HTTP

typedef uint8_t uchar;   // 8비트
typedef uint16_t ushort; // 16비트
typedef uint32_t uint;   // 32비트
typedef uint8_t uint4_t; // 4비트


class PcapParser
{
public:
    //PcapParser(const string &dev); //실시간
    PcapParser(const string &file); //파일 읽고 파싱
    int ParsePcapFile();
    //int Capture_and_parse(int captureTimeSeconds); 

private:
    struct Ether
    {
        uchar SA[6];
        uchar DA[6];
        ushort ether_type;
    };

    struct IP
    {
        uchar version; // version+IHL
        uchar tos;
        ushort total_len;
        ushort id;
        ushort flag; // flag 3 + offset 13
        uchar ttl;
        uchar protocol_id;
        ushort checksum;
        uint src_ip;
        uint dst_ip;
    };
    
    struct TCP
    {
        ushort src_port;
        ushort dst_port;
        uint seq;
        uint ack;
        uint4_t offset;
        uint4_t flags;
        ushort window_size;
        ushort checksum;
        ushort urgent_pointer;

    };
    struct Packet
    {
        Ether eth;
        IP ip;
        TCP tcp;
        uchar *payload;
    };
    #pragma pack(pop)
    
    pcap_t *handle;
    void Parse(pcap_pkthdr* header, const u_char *data, uint caplen);
};

PcapParser::PcapParser(const string &file)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(file.c_str(), errbuf);
    if (handle == nullptr)
    {
        cerr << "Could not open file: " << errbuf << endl;
        return;
    }
    else{
        cout << "success to open file" << endl;
    }
}

void PcapParser::Parse(pcap_pkthdr* header, const u_char *data, uint caplen)
{
    Packet* packet = new Packet;
    uchar *now = reinterpret_cast<uchar *>(&packet);

    ushort etherType = ntohs(packet.eth.ether_type);

    if (etherType == 0x0800) {
        
        int ethernetHeaderLength = sizeof(Ether);
        //cout << "size: " <<ethernetHeaderLength <<endl;
        // 14 출력되는중

        uchar *ipHeaderStart = now+ethernetHeaderLength;

        ushort totallen = ntohs(packet.ip.total_len);
        uchar ip_header_len = (packet.ip.version & 0x0F) * 4;
        uchar tcp_header_len = (packet.tcp.offset >> 4) * 4;

        ushort srcPort = ntohs(packet.tcp.src_port);
        ushort dstPort = ntohs(packet.tcp.dst_port);

        uchar pro_id = packet.ip.protocol_id;

        int dataLength = totallen - ip_header_len - tcp_header_len;
        
        //cout << "datalength: " << dataLength << endl;
        u_char *datastart = ipHeaderStart + ip_header_len + tcp_header_len;

        if (pro_id == 6 &&(srcPort == 80 || dstPort==80) && (dataLength>0)){
            
            cout << "============new packet==========" << endl;
            cout << "Timestamp: " << dec << header->ts.tv_sec << "." << header->ts.tv_usec << endl;
            cout << "Capture Length: " << dec << header->caplen << " bytes" << endl;

            cout << "--------Ethernet frame-----------" << endl;
            cout << "Ehter type: " << hex << setw(4) << setfill('0') << ntohs(packet.eth.ether_type) << dec << endl;
            cout << "Src MAC: ";
            for (int i = 0; i < 6; i++)
            {
                cout << hex << setw(2) << setfill('0') << int(packet.eth.SA[i]);
                if (i < 5)
                {
                    cout << ":";
                }
            }
            cout << dec << endl;

            cout << "Dst MAC: ";
            for (int i = 0; i < 6; i++)
            {
                cout << hex << setw(2) << setfill('0') << int(packet.eth.DA[i]);
                if (i < 5)
                {
                    cout << ":";
                }
            }
            cout << dec << endl;

            cout << "--------------IP------------------" << endl;
            cout << "Protocol ID: " << hex << setw(2) << setfill('0') << int(pro_id) << dec << endl;
            
            uint32_t src = packet.ip.src_ip; 
            uint32_t dst = packet.ip.dst_ip;

            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN]; 
            
            inet_ntop(AF_INET, &src, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &dst, dst_ip_str, INET_ADDRSTRLEN);

            printf("src IP : %s\n", src_ip_str);
            printf("dst IP : %s\n", dst_ip_str);
            
            
            cout << "total length : " << totallen << endl;
            cout << "IP header length : " << int(ip_header_len) << " bytes" << endl;
            //20으로 나오는중
            cout << "TCP header length : " << int(tcp_header_len) << " bytes" << endl;
        

            cout << "---------------TCP------------------" << endl;
            cout << "Src port: " << srcPort << endl;
            cout << "Dst port: " << dstPort << endl;
            cout << "Data:" << endl;
            
            datastart = reinterpret_cast<u_char*>(now+ethernetHeaderLength + int(ip_header_len) + int(tcp_header_len));
            packet.payload = datastart;

            for (int i = 0; i < dataLength; ++i)
            {
                cout << hex << setw(2) << setfill('0') << static_cast<int>(packet.payload[i]) << " ";
                if ((i + 1) % 16 == 0)
                {
                    cout << endl;
                }
            }

            cout << "___data end___" << endl; 
            

        }
        else{}
    }
    else{}
}


int PcapParser::ParsePcapFile()
{
    struct pcap_pkthdr header;
    const u_char *data;

    while ((data = pcap_next(handle, &header)) != nullptr)
    {
        Parse(&header, data, header.caplen);

    }
    return 0;
}

int main()
{
    string file = "test_pcap.pcapng";
    PcapParser pcapParser(file);
    int result = pcapParser.ParsePcapFile();
    return result;
}
