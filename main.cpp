#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <map>
#include <set>

#include <pcap.h>

#include "mac.h"
#include "radiotabhdr.h"
#include "IEEhdr.h"

using namespace std;

struct info{
    Mac BSSID;
    int8_t PWR;
    uint32_t Beacons;
    string ESSID;
};

set<Mac> beacon, probe;
map<Mac, info> beaconMap;
map<Mac, info> probeMap;


void usage(){
    printf("syntax : airodump <interface>");
    printf("sample : airodump mon0");
    return;
}

void printInfo(){
    system("clear");
    printf("BSSID              PWR  Beacons    AUTH ESSID\n");
    for(auto it = beacon.begin(); it != beacon.end(); it++){
        cout << std::string(beaconMap[*it].BSSID) << "   " << (int)(beaconMap[*it].PWR) << "   " << (int)(beaconMap[*it].Beacons) << "\t   " << beaconMap[*it].ESSID << endl;;
    }
    printf("BSSID              PWR  Beacons    AUTH ESSID\n");
    for(auto it = probe.begin(); it != probe.end(); it++){
        cout << std::string(probeMap[*it].BSSID) << " " << probeMap[*it].PWR << " " << probeMap[*it].Beacons << " " << probeMap[*it].ESSID << endl;;
    }
}

int main(int argc, char* argv[]){
    if(argc != 2){
        usage();
        exit(-1);
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}
    
    printInfo();
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            cout << "pcap_next_ex return "<<res<<'('<<pcap_geterr(handle)<<')'<<endl;
            break;
        }

        
        
        radioTabHdr* radio = (radioTabHdr *) packet;
        
        ieeHdr* iee = (ieeHdr*) (packet + radio->len);
        
        #define OFFSET 12
        if(iee->subtype != BEACON_SUBTYPE && iee->subtype != PROBE_SUBTYPE) continue;
        ssidHdr* ssidh = (ssidHdr*)(((char*)iee)+BEACON_HEADER_SIZE+OFFSET);

        uint8_t ssid_len = ssidh->len;
        char* ssid = (((char*)iee)+BEACON_HEADER_SIZE+OFFSET)+SSID_SIZE;
        // printf("cautch! %X\n",iee->subtype);
        // cout << "BSSID : " << string(iee->bssid) << endl;
        // printf("PWR : %d\n", radio->antenna);
        // printf("ssid len : %d\n", ssid_len&0xff);
        // for(int i = 0 ; i < ssid_len; i++){
        //     printf("%c ",ssid[i]&0xff);
        // }
        // puts("");
        
        string ESSID(ssid, ssid_len);
        info data{iee->bssid, radio->antenna, 0, ESSID};
        if(PROBE_SUBTYPE == iee->subtype){
            probe.insert(iee->bssid);
            auto item = probeMap.find(iee->bssid);
            if (item != probeMap.end()) {
                probeMap[iee->bssid] = data;
            } 
            probeMap[iee->bssid].PWR = radio->antenna;
            probeMap[iee->bssid].Beacons += 1;
        }
        if(BEACON_SUBTYPE == iee->subtype){
            beacon.insert(iee->bssid);
            auto item = beaconMap.find(iee->bssid);
            if (item != beaconMap.end()) {
                beaconMap[iee->bssid] = data;
            } 
            beaconMap[iee->bssid].PWR = radio->antenna;
            beaconMap[iee->bssid].Beacons += 1;
        }
        printInfo();
    }
    pcap_close(handle);
}