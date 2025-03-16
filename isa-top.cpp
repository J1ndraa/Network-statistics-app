/*
 * @file isa-top.cpp
 * @name ISA-TOP Project
 * @author Halva Jindřich (xhalva05)
 * @brief Application for obtaining statistics about network traffic. Project to subject ISA (VUT FIT).
 * @date October 2024
 */

#include <iostream>
#include <curses.h>
#include <pcap.h>
#include <string.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <vector>
#include <algorithm>
#include <thread>
#include <mutex>
#include <chrono>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <mutex>


using namespace std;
pcap_t *handle;
char* interface;
char* sort_option = "b";
int update_timeout = 1;
struct bpf_program fp;

//unit structure for storing the data about a communication
struct Unit {
    string src_ip;
    string dst_ip;
    string protocol;
    int Rx = 0;
    int Tx = 0;
    int rx_packets = 0;
    int tx_packets = 0;
};

//vector for storing the unique communication units
vector <Unit> units;

//mutex for the vector of communication units
mutex mutex_for_units;

///////////////////////////////////////////////////_FUNCTIONS_///////////////////////////////////////////////////////////

//check if the arguments are correct
//interface is mandatory, sort and timeout is optional
void checkArgs(int argc, char *argv[]) {
    if (argc == 3) {
        if (strcmp(argv[1], "-i") == 0) {
            interface = argv[2];
        }
    }
    else if(argc == 5){
        if ((strcmp(argv[1], "-i") == 0) && (strcmp(argv[3], "-s") == 0) && (strcmp(argv[4], "b") == 0 || strcmp(argv[4], "p") == 0)) {
            interface = argv[2];
            sort_option = argv[4];
        }
        else if ((strcmp(argv[1], "-i") == 0) && (strcmp(argv[3], "-t") == 0)) {
            interface = argv[2];
            update_timeout = atoi(argv[4]);
        }
    }
        else if(argc == 7){
        if ((strcmp(argv[1], "-i") == 0) && (strcmp(argv[3], "-s") == 0) && (strcmp(argv[4], "b") == 0 || strcmp(argv[4], "p") == 0) && (strcmp(argv[5], "-t") == 0)) {
            interface = argv[2];
            sort_option = argv[4];
            update_timeout = atoi(argv[6]);
        }
    }
    else{
        cerr << "Usage: ./isa-top -i interface [-s b|p] [-t timeout]" << endl;
        cerr << "-s: b|p - sort the output by bytes/packets/s" << endl;
        cerr << "-t: Timeout between statistics update, in seconds" << endl;
        exit(1);
    }
}

//handling the packets
class Handler {
public:
    //main function, controls the packet handling
    //it calls the appropriate handler for IPv4 or IPv6
    static void PacketHandler(u_char *arguments, const struct pcap_pkthdr *header_ptr, const u_char *packet_ptr) {
        struct ether_header *ethHeader = (struct ether_header *)packet_ptr;
        u_int16_t ether_type = ntohs(ethHeader->ether_type);
        auto len = header_ptr->len;
        string src_ip;
        string dst_ip;
        string protocol;
        string src_port;
        string dst_port;

        //check if the packet is IPv4 or IPv6 and call the appropriate handler
        if(ether_type == ETHERTYPE_IP){
            IPv4Handler(packet_ptr, &src_ip, &dst_ip, &protocol, &src_port, &dst_port);
        }
        else if(ether_type == ETHERTYPE_IPV6){
            IPv6Handler(packet_ptr, &src_ip, &dst_ip, &protocol, &src_port, &dst_port);
        }

        //add port number to the IP address
        if(src_port != "" && dst_port != ""){
            src_ip += ":" + src_port;
            dst_ip += ":" + dst_port;
        }
        lock_guard<mutex> lock(mutex_for_units);

        //check if the source and destination IP addresses are already in the vector
        //if they are, update the values, if not, add them to the vector
        for (long unsigned int i = 0; i < units.size(); i++) {
            if (units[i].src_ip == src_ip && units[i].dst_ip == dst_ip) {
                units[i].Rx += len;
                units[i].rx_packets++;
                return;
            }
            else if (units[i].src_ip == dst_ip && units[i].dst_ip == src_ip) {
                units[i].Tx += len;
                units[i].tx_packets++;
                return;
            }
        }

        //Captured communication is new, add it to the vector as new unit
        Unit new_unit;
        new_unit.src_ip = src_ip;
        new_unit.dst_ip = dst_ip;
        new_unit.protocol = protocol;
        new_unit.Rx = len;
        new_unit.rx_packets = 1;
        new_unit.Tx = 0;
        new_unit.tx_packets = 0;
        units.push_back(new_unit);
    }

    //IPv4 handler
    //Save the source and destination IP addresses and the protocol to the variables
    static void IPv4Handler(const u_char *packet_ptr, string* src_ip, string* dst_ip, string* protocol, string* src_port, string* dst_port) {
       
        struct ip *ip_header = (struct ip *)(packet_ptr + sizeof(struct ether_header)); //skip Ethernet header

        *src_ip = inet_ntoa(ip_header->ip_src);
        *dst_ip = inet_ntoa(ip_header->ip_dst);
       
        struct protoent *proto = getprotobynumber(ip_header->ip_p);
        *protocol = proto->p_name;

        //get port numbers
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet_ptr + sizeof(struct ether_header) + sizeof(struct ip));
            *src_port = to_string(ntohs(tcp_header->th_sport));
            *dst_port = to_string(ntohs(tcp_header->th_dport));
        }
        else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet_ptr + sizeof(struct ether_header) + sizeof(struct ip));
            *src_port = to_string(ntohs(udp_header->uh_sport));
            *dst_port = to_string(ntohs(udp_header->uh_dport));
        }
    }

    //IPv6 handler
    //Save the source and destination IP addresses and the protocol to the variables
    static void IPv6Handler(const u_char *packet_ptr, string* src_ip, string* dst_ip, string* protocol, string* src_port, string* dst_port) {
        
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet_ptr + sizeof(struct ether_header)); //skip Ethernet header
        
        char source_ip[INET6_ADDRSTRLEN];
        char dest_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6_header->ip6_src, source_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->ip6_dst, dest_ip, INET6_ADDRSTRLEN);  
        *src_ip = "[" + (string)source_ip + "]";
        *dst_ip = "[" + (string)dest_ip + "]";

        struct protoent *proto = getprotobynumber(ip6_header->ip6_nxt);
        *protocol = proto->p_name;

        //get port numbers
        if (ip6_header->ip6_nxt == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet_ptr + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            *src_port = to_string(ntohs(tcp_header->th_sport));
            *dst_port = to_string(ntohs(tcp_header->th_dport));
        }
        else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet_ptr + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            *src_port = to_string(ntohs(udp_header->uh_sport));
            *dst_port = to_string(ntohs(udp_header->uh_dport));
        }
    }
};

//transfer bites data to Kb/Mb/Gb per second
//or packets to Kp/Mp/Gp per second
double transferData(int data, string* extra_suffix){
    double new_data = (double)data/(double)update_timeout;
    cerr << data << " " << new_data << endl;
    *extra_suffix = "";
    if(new_data > 1000){
        if(new_data > 1000000){
            if(new_data > 1000000000){
                *extra_suffix = "G";
                return new_data/1000000000;
            }
            *extra_suffix = "M";
            return new_data/1000000;
        }
        *extra_suffix = "K";
        return new_data/1000;
    }
    return new_data;
}

//print the output on the screen
void printUnits(){
    //clear the screen for new statistics
    clear();
    mvprintw(0, 0, "SrcIP:Port"); mvprintw(0, 50, "DstIP:Port"); mvprintw(0, 100, "Proto"); mvprintw(0, 115, "Rx"); mvprintw(0, 131, "Tx");
    mvprintw(1, 111, "b/s"); mvprintw(1, 118, "p/s");   mvprintw(1, 127, "b/s"); mvprintw(1, 134, "p/s");
    mvprintw(2, 0, "____________________________________________________________________________________________________________________________________________");
    
    //pick the first 10 communications and print them on the screen
    for (size_t i = 0; i < units.size() && i < 10; i++) {
        string extra_suffix;
        double data;
        //print the source and destination IP addresses and the protocol
        mvprintw((i+3), 0, "%s", units[i].src_ip.c_str());
        mvprintw((i+3), 50, "%s", units[i].dst_ip.c_str());
        mvprintw((i+3), 100, "%s", units[i].protocol.c_str());

        //print the transfered data and packets per second
        data = transferData(units[i].Rx, &extra_suffix);
        mvprintw((i+3), 111, "%.1f%s", data, extra_suffix.c_str());

        data = transferData(units[i].rx_packets, &extra_suffix);
        mvprintw((i+3), 119, "%.1f%s", data, extra_suffix.c_str());
        
        data = transferData(units[i].Tx, &extra_suffix);
        mvprintw((i+3), 127, "%.1f%s", data, extra_suffix.c_str());
        
        data = transferData(units[i].tx_packets, &extra_suffix);
        mvprintw((i+3), 134, "%.1f%s\n", data, extra_suffix.c_str());
    }
    //show data on the screen
    refresh();
}

//compare two units by the number of bytes
bool compareByBytes(const Unit& x, const Unit& y) {

    return (x.Rx + x.Tx) > (y.Rx + y.Tx);
}

//compare two units by the number of packets
bool compareByPackets(const Unit& x, const Unit& y) {
    return (x.rx_packets + x.tx_packets) > (y.rx_packets + y.tx_packets);
}

//sort the vector and call the print function every second
void OutputHandleThread() {
    while (1) {
        if(1){
            lock_guard<mutex> lock(mutex_for_units);
            if (strcmp(sort_option, "p") == 0) {
                sort(units.begin(), units.end(), compareByPackets);
            }
            else if(strcmp(sort_option, "b") == 0){
                sort(units.begin(), units.end(), compareByBytes);
            }
            printUnits();
            units.clear();
        }
        this_thread::sleep_for(std::chrono::seconds(update_timeout));
    }
}

//Packet capturing
void CapturePacketThread() {
    pcap_loop(handle, 0, Handler::PacketHandler, NULL);
}

//handle the interrupt signal and close the interface
void handleInterruptSignal(int signal) {
    cerr << "Interrupt signal received." << endl;
    pcap_close(handle);
	pcap_freecode(&fp);
	if(units.size() > 0){
        units.clear();
    }
    exit(2);
}

///////////////////////////////////////////////////_MAIN_///////////////////////////////////////////////////////////

int main(int argc, char *argv[]) {
    char *filter = "ip or ip6 or tcp or udp or icmp or icmp6";
    char error_buffer[PCAP_ERRBUF_SIZE];

    //handle the interrupt signal if it occurs
    signal(SIGINT, handleInterruptSignal);

    //check the arguments
    checkArgs(argc, argv);

    //check if the interface is valid
    if (pcap_lookupdev(error_buffer) == NULL) {
        cerr << "Invalid interface: " << error_buffer << endl;
        return 1;
    }

    //open the interface
    handle = pcap_open_live(interface,BUFSIZ,1,1000,error_buffer);
    if(handle == NULL){
        cerr << "Error: " << error_buffer << endl;
        return 1;
    }

    //check if the interface provides Ethernet headers
    if (pcap_datalink(handle) != DLT_EN10MB) {
        cerr << "Interface doesn't provide Ethernet headers" << endl;
        return 1;
    }

    //compile the filter
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    //set the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    //initialize the ncurses screen
    initscr();
    noecho();

    //create the threads
    //one for packet capturing
    //one for output handling
    thread OutputThread(OutputHandleThread);
    thread CaptureThread(CapturePacketThread);

    //wait for the threads to finish
    OutputThread.join();
    CaptureThread.join();

    //close the screen
    endwin();

    //close the interface and free the memory of the filter
    pcap_close(handle);
    pcap_freecode(&fp);

    return 0;
}

///////////////////////////////////////////////////_END_///////////////////////////////////////////////////////////
