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


class PcapParser
{
public:
    //PcapParser(const string &dev); //실시간
    PcapParser(const string &file); //파일 읽고 파싱
    int ParsePcapFile();
    //int PcapParser::Capture(int capturetime)
    ~PcapParser();

    //int Capture_and_parse(int capturetime); 

private:
    struct Ether
    {
        uchar DA[6];
        uchar SA[6];
        ushort ether_type;
    };

    struct IP
    {
        uchar version;
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
        uchar offsets; //offset+flag
        ushort window_size;
        ushort checksum;
        ushort urgent_pointer;
        uchar nop1;
        uchar nop2;
        uchar kind;
        uchar length;
        uint ts_value;
        uint ts_reply;

    };

    struct Packet
    {
        Ether eth;
        IP ip;
        TCP tcp;
        u_char payload[1000];
    };
    #pragma pack(pop)

    
    pcap_t *handle;
    void Parse(pcap_pkthdr* header,const u_char *data, uint caplen);
    void parsebody(const u_char *payload, int dataLength);
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

PcapParser::~PcapParser()
{
    if (handle != nullptr) {
        pcap_close(handle);
    }
}


void PcapParser::Parse(pcap_pkthdr* header,const u_char *data, uint caplen)
{
    Packet* packet = (Packet *)data;

    ushort etherType = ntohs(packet->eth.ether_type);

    if (etherType == 0x0800){
        
        int ethernetHeaderLength = sizeof(Ether);
        //cout << "size: " <<ethernetHeaderLength <<endl;
        //14
        const u_char *ipHeaderStart = data + ethernetHeaderLength;

        ushort totallen = ntohs(packet->ip.total_len);
        uchar ip_header_len = (packet->ip.version & 0x0F) * 4;
        uchar tcp_header_len = (packet->tcp.offsets >> 4) * 4;

        ushort srcPort = ntohs(packet->tcp.src_port);
        ushort dstPort = ntohs(packet->tcp.dst_port);

        uchar pro_id = packet->ip.protocol_id;

        int dataLength = caplen - ethernetHeaderLength - ip_header_len - tcp_header_len;
        if (pro_id == 6 &&(srcPort == 80 || dstPort==80) && (dataLength>0)){


            cout << "-------------------new packet--------------------" << endl;
            cout << "Timestamp: " << dec << header->ts.tv_sec << "." << header->ts.tv_usec << endl;
            cout << "Capture Length: " << dec << header->caplen << " bytes" << endl;
            
            cout << "--------Ethernet frame-----------" << endl;
            cout << "Ehter type: " << hex << setw(4) << setfill('0') << ntohs(packet->eth.ether_type) << dec << endl;

            cout << "Src MAC: ";
            for (int i = 0; i < 6; i++)
            {
                cout << hex << setw(2) << setfill('0') << int(packet->eth.SA[i]);
                if (i < 5)
                {
                    cout << ":";
                }
            }
            cout << dec << endl;

            cout << "Dst MAC: ";
            for (int i = 0; i < 6; i++)
            {
                cout << hex << setw(2) << setfill('0') << int(packet->eth.DA[i]);
                // 왼쪽은 0으로 채운다
                if (i < 5)
                {
                    cout << ":";
                }
            }
            cout << dec << endl;

            cout << "--------------IP------------------" << endl;
            cout << "Protocol ID: " << hex << setw(2) << setfill('0') << int(pro_id) << dec << endl;
            
            //fixedip...???
            uint32_t src_ip = packet->ip.src_ip; 
            uint32_t dst_ip = packet->ip.dst_ip;

            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN]; 
            
            inet_ntop(AF_INET, &src_ip, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &dst_ip, dst_ip_str, INET_ADDRSTRLEN);

            printf("src IP : %s\n", src_ip_str);
            printf("dst IP : %s\n", dst_ip_str);

            cout << "total length : " << totallen << endl;
            cout << "IP header length : " << int(ip_header_len) << endl;
            cout << "TCP header length : " << int(tcp_header_len) << endl;

            cout << "------------------TCP--------------------" << endl;
            cout << "Src port: " << srcPort << endl;
            cout << "Dst port: " << dstPort << endl;

            const u_char *datastart = ipHeaderStart + sizeof(IP) + sizeof(TCP);
            memcpy(packet->payload, datastart, dataLength);

            cout << "------------------------------------" << endl;
            if (dataLength > 0)
            {
                cout << "Data:" << endl;
                for (int i = 1; i < dataLength; ++i)
                
                ///r/n 이 .. 으로 나옴 —> 먼저 0d0a로 나눠서 그 이후에 바꾸기
                /*
                {
                    
                    char c = packet->payload[i];
                    if (isprint(c))
                    {
                        cout << c;
                    }
                    else{
                        cout << ".";
                    }
                    //

                }
                */
               {
                cout << hex << setw(2) << setfill('0') << static_cast<int>(packet->payload[i]) << " ";
               }
               
            }
            cout << "…………………………data end" << endl;    
        }
        else{}
    }
    else{}
}

/*
//여기에서 http 메시지 파싱
void PcapParser::parsebody(const u_char *payload, int dataLength)
{

    for (int i=0; i<dataLength; ++i){
        char c = payload[i];
        if
    } 

}
*/


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
/*
int PcapParser::Capture(int capturetime)
{
    struct pcap_pkthdr header;
    const u_char *packet;
    time_t starttime = time(nullptr);

    while (time(nullptr) - startTime < capturetime)
    {
        if (handle)
        {
            packet = pcap_next(handle, &header);
            if (packet == nullptr)
            {
                break;
            }
            Parse(packet, header.caplen);

        }

        else
        {
            break;
        }
    }
    return 0;
}*/

int main()
{
    string file = "test3_pcap.pcapng";
    // content-type='application/json'있는거 

    //string file = "test1.pcap.pcapng";
    //content-type='application/ocsp-request,,,'
    PcapParser pcapParser(file);
    int result = pcapParser.ParsePcapFile();
    return result;
}







/*#include <pcap.h>
#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <iomanip> 
using namespace std;
#pragma pack(push, 1)
#pragma pack(pop)



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
        uint4_t version;
        uint4_t header_length;
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
        uchar offset;
        uchar flags;
        ushort window_size;
        ushort checksum;
        ushort urgent_pointer;
    };

    struct Packet
    {
        Ether eth;
        IP ip;
        TCP tcp;
        u_char payload;
    };

    
    pcap_t *handle;
    void Parse(const u_char *data, uint caplen);
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


void PcapParser::Parse(const u_char *data, uint caplen)
{
    Packet* packet = (Packet *)data;

    ushort etherType = ntohs(packet->eth.ether_type);

    if (etherType == 0x0800){
        
        int ethernetHeaderLength = sizeof(Ether);
        cout << "size: " <<ethernetHeaderLength <<endl;
        const u_char *ipHeaderStart = data + ethernetHeaderLength;

        cout << "-------------------new packet--------------------" << endl;
        cout << "-------------------------------------------------" << endl;
        cout << "Ehter type: " << hex << setw(4) << setfill('0') << ntohs(packet->eth.ether_type) << dec << endl;

        cout << "Dst MAC: ";
        for (int i = 0; i < 6; i++)
        {
            cout << hex << setw(2) << setfill('0') << int(packet->eth.DA[i]);
            // 왼쪽은 0으로 채운다
            if (i < 5)
            {
                cout << ":";
            }
        }
        cout << dec << endl;

        cout << "Src MAC: ";
        for (int i = 0; i < 6; i++)
        {
            cout << hex << setw(2) << setfill('0') << int(packet->eth.SA[i]);
            if (i < 5)
            {
                cout << ":";
            }
        }
        cout << dec << endl;

        ushort totallen = ntohs(packet->ip.total_len);
        uchar ip_header_len = (packet->ip.header_length) * 4;
        uchar tcp_header_len = (packet->tcp.offset >> 4) * 4;

        uint src = packet->ip.src_ip;
        uint dst = packet->ip.dst_ip;
        cout << "total length : " << totallen << endl;
        cout << "IP header length : " << ip_header_len << endl;
        cout << "TCP header length : " << tcp_header_len << endl;
    

        cout << "------------------------------------" << endl;
        cout << "Dst IP: " << int((dst >> 24) & 0xFF) << "." << int((dst >> 16) & 0xFF) << "." << int((dst >> 8) & 0xFF) << "." << int(dst & 0xFF) << endl;
        cout << "Src IP: " << int((src >> 24) & 0xFF) << "." << int((src>> 16) & 0xFF) << "." << int((src >> 8) & 0xFF) << "." << int(src & 0xFF) << endl;
        cout << "Protocol ID: " << hex << setw(4) << setfill('0') << int(packet->ip.protocol_id) << dec << endl;

        ushort srcPort = ntohs(packet->tcp.src_port);
        ushort dstPort = ntohs(packet->tcp.dst_port);

        cout << "------------------------------------" << endl;
        cout << "Dst port: " << dstPort << endl;
        cout << "Src port: " << srcPort << endl;

       
        int dataLength = caplen - ethernetHeaderLength - sizeof(IP) - sizeof(TCP);
        const u_char *datastart = ipHeaderStart + sizeof(IP) + sizeof(TCP);

        cout << "------------------------------------" << endl;
        if (dataLength > 0)
        {
            cout << "Data:" << endl;
            for (int i = 0; i < dataLength; ++i)
            {
                cout << hex << setw(2) << setfill('0') << int(datastart[i]) << " ";
                if ((i + 1) % 16 == 0)
                {
                    cout << endl;
                }
            }
        }
        cout << "……………………………..data end" << endl;    
    }
    else{}
}

int PcapParser::ParsePcapFile()
{
    struct pcap_pkthdr header;
    const u_char *data;

    while ((data = pcap_next(handle, &header)) != nullptr)
    {
        Parse(data, header.caplen);
        cout << "Timestamp: " << dec << header.ts.tv_sec << "." << header.ts.tv_usec << endl;
        cout << "Capture Length: " << dec << header.caplen << " bytes" << endl;
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
    Packet packet;
    memcpy(&packet, data, sizeof(data));
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



#include <pcap.h>
#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <iomanip> 
using namespace std;

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
        uint4_t version;
        uint4_t header_length;
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
        uchar offset;
        uchar flags;
        ushort window_size;
        ushort checksum;
        ushort urgent_pointer;
    };

    struct Packet
    {
        Ether eth;
        IP ip;
        TCP tcp;
    };
    
    pcap_t *handle;
    void Parse(const u_char *data, uint caplen);
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


void PcapParser::Parse(const u_char *data, uint caplen)
{
    Packet packet;
    memcpy(&packet, data, sizeof(Packet));

    ushort etherType = ntohs(packet.eth.ether_type);

    if (etherType == 0x0800){
        
        int ethernetHeaderLength = sizeof(Ether);
        const u_char *ipHeaderStart = data + ethernetHeaderLength;

        cout << "-------------------new packet--------------------" << endl;
        cout << "-------------------------------------------------" << endl;
        cout << "Ehter type: " << hex << setw(4) << setfill('0') << ntohs(packet.eth.ether_type) << dec << endl;

        cout << "Dst MAC: ";
        for (int i = 0; i < 6; i++)
        {
            cout << hex << setw(2) << setfill('0') << int(packet.eth.DA[i]);
            // 왼쪽은 0으로 채운다
            if (i < 5)
            {
                cout << ":";
            }
        }
        cout << dec << endl;

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

        ushort totallen = ntohs(packet.ip.total_len);
        uchar ip_header_len = (packet.ip.version & 0x0F) * 4;
        uchar tcp_header_len = (packet.tcp.offset >> 4) * 4;

        uint src = packet.ip.src_ip;
        uint dst = packet.ip.dst_ip;
        cout << "total length : " << totallen << endl;
        cout << "IP header length : " << ip_header_len << endl;
        cout << "TCP header length : " << tcp_header_len << endl;
        
        //uint fixedip = 0xC0A84005;


        cout << "------------------------------------" << endl;
        cout << "Dst IP: " << int((dst >> 24) & 0xFF) << "." << int((dst >> 16) & 0xFF) << "." << int((dst >> 8) & 0xFF) << "." << int(dst & 0xFF) << endl;
        cout << "Src IP: " << int((src >> 24) & 0xFF) << "." << int((src>> 16) & 0xFF) << "." << int((src >> 8) & 0xFF) << "." << int(src & 0xFF) << endl;
        cout << "Protocol ID: " << hex << setw(4) << setfill('0') << int(packet.ip.protocol_id) << dec << endl;

        ushort srcPort = ntohs(packet.tcp.src_port);
        ushort dstPort = ntohs(packet.tcp.dst_port);

        cout << "------------------------------------" << endl;
        cout << "Dst port: " << dstPort << endl;
        cout << "Src port: " << srcPort << endl;

       
        int dataLength = caplen - ethernetHeaderLength - sizeof(IP) - sizeof(TCP);
        const u_char *datastart = ipHeaderStart + sizeof(IP) + sizeof(TCP);

        cout << "------------------------------------" << endl;
        if (dataLength > 0)
        {
            cout << "Data:" << endl;
            for (int i = 0; i < dataLength; ++i)
            {
                cout << hex << setw(2) << setfill('0') << int(datastart[i]) << " ";
                if ((i + 1) % 16 == 0)
                {
                    cout << endl;
                }
            }
        }
        cout << "...................................data end" << endl;    
    }
    else{}
}

int PcapParser::ParsePcapFile()
{
    struct pcap_pkthdr header;
    const u_char *data;

    while ((data = pcap_next(handle, &header)) != nullptr)
    {
        Parse(data, header.caplen);
        cout << "Timestamp: " << dec << header.ts.tv_sec << "." << header.ts.tv_usec << endl;
        cout << "Capture Length: " << dec << header.caplen << " bytes" << endl;
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


#include <pcap.h>
#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <iomanip> 
using namespace std;

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
    //PcapParser(const string &dev);
    PcapParser(const string &file);
    int ParsePcapFile();
    //int Capture_and_parse(int captureTimeSeconds);

private:
    struct Ether
    {
        uchar DA[6];
        uchar SA[6];
        ushort ether_type;
    };

    struct IP
    {
        uint4_t version;
        uint4_t header_length;
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
        uchar res;
        ushort window_size;
        ushort checksum;
        ushort urgent_pointer;
    };
    struct packet
    {
        Ether eth;
        IP ip;
        TCP tcp;
    };
    
    pcap_t *handle;
    void Parse(const u_char *packet, uint caplen);
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


void PcapParser::Parse(const u_char *packet, uint caplen)
{
    const int EtherHeaderSize = 14;
    if (caplen < EtherHeaderSize)
    {
        cerr << "Invalid Ethernet frame." << endl;
        return;
    }

    Ether *etherHeader = reinterpret_cast<Ether *>(const_cast<u_char *>(packet));
    ushort etherType = ntohs(etherHeader->ether_type);

    cout << "Packet Captured. Length: " << dec << caplen << " bytes" << endl;
        cout << "Timestamp: " << dec << time(nullptr) << endl;
        cout << "Capture Length: " << dec << caplen << " bytes" << endl;

        
        cout << "------------------------------------" << endl;
        cout << "Dst MAC: ";
        for (int i = 0; i < 6; i++)
        {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(etherHeader->DA[i]);
            // 왼쪽은 0으로 채운다
            if (i < 5)
            {
                cout << ":";
            }
        }
        cout << dec << endl;

        cout << "Src MAC: ";
        for (int i = 0; i < 6; i++)
        {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(etherHeader->SA[i]);
            if (i < 5)
            {
                cout << ":";
            }
        }
        cout << dec << endl;

        cout << "Ehter type: " << hex << setw(4) << setfill('0') << ntohs(etherHeader->ether_type) << dec << endl;
        cout << "------------------------------------" << endl;


    if (etherType == 0x0800) // IPv4
    {
        IP *ip = reinterpret_cast<IP *>(const_cast<u_char *>(packet+EtherHeaderSize));
       
        if (caplen < 20){
            cerr << "Invalid IP packet." << endl;
            return;
        }

        cout << "Dst IP: ";
        cout << static_cast<int>(ip->dst_ip >> 24) << "." << static_cast<int>((ip->dst_ip >> 16) & 0xFF) << "." << static_cast<int>((ip->dst_ip >> 8) & 0xFF) << "." << static_cast<int>(ip->dst_ip & 0xFF) << endl;
        cout << "Src IP: ";
        cout << static_cast<int>(ip->src_ip >> 24) << "." << static_cast<int>((ip->src_ip >> 16) & 0xFF) << "." << static_cast<int>((ip->src_ip >> 8) & 0xFF) << "." << static_cast<int>(ip->src_ip & 0xFF) << endl;
        cout << "Protocol: " << hex << setw(4) << setfill('0') << static_cast<int>(ip->protocol_id) << dec << endl;
        cout << "------------------------------------" << endl;
        
        const int ipHeaderLength = (ip->header_length & 0xF) * 4;
        const u_char *tcpPacket = packet + ipHeaderLength;

        TCP *tcp = reinterpret_cast<TCP *>(const_cast<u_char *>(tcpPacket));

        ushort srcPort = ntohs(tcp->src_port);
        ushort dstPort = ntohs(tcp->dst_port);

      
        cout << "Dst port: " << dstPort << endl;
        cout << "Src port: " << srcPort << endl;

        int dataLength = caplen - EtherHeaderSize - sizeof(IP) - sizeof(TCP);
        const u_char *data = tcpPacket + sizeof(TCP);
        if (dataLength > 0)
        {
            cout << "Data:" << endl;
            for (int i = 0; i < dataLength; ++i)
            {
                cout << hex << setw(2) << setfill('0') << static_cast<int>(data[i]) << " ";
                if ((i + 1) % 16 == 0)
                {
                    cout << endl;
                }
            }
        }
        cout << "...................................data end" << endl;
    }


    else{}
}

int PcapParser::ParsePcapFile()
{
    struct pcap_pkthdr header;
    const u_char *packet;

    while ((packet = pcap_next(handle, &header)) != nullptr)
    {
        Parse(packet, header.caplen);
        
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

*/