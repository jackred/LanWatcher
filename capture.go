package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"encoding/binary"
	// "strings"
	"time"
	"net"
	"bufio"
	"strconv"
	"os"
)

type HostSnapshot struct {
	Timestamp time.Time  // Time when the snapshot was taken
	IpAddress string
	MacAddress string
	Reception NetworkTotalStatistic  // Rx
	Transmission NetworkTotalStatistic  // Tx
}

type NetworkTotalStatistic struct {
	TotalSize int64
	PacketCount int64
}


var (
	device       string = "wlp4s0:"
	snapshot_len int32  = 8192
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 1
	handle       *pcap.Handle
	mapSnap      HostSnapshot
)

func ip2int(ip net.IP) uint32{
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func displayAllUsers(mapSnap map[string]HostSnapshot){
	for key, value := range mapSnap {
		fmt.Println("=================================================")
		fmt.Println("key: ", key)
		fmt.Println("Mac host:",value.MacAddress)
		fmt.Println("Last time:",value.Timestamp)
		fmt.Println("-----Reception: ")
		fmt.Println("Total size: ",value.Reception.TotalSize)
		fmt.Println("Packet count: ",value.Reception.PacketCount)
		fmt.Println("----Transmission: ")
		fmt.Println("Total size: ",value.Transmission.TotalSize)
		fmt.Println("Packet count: ",value.Transmission.PacketCount)
		fmt.Println("=================================================")
	}
}


func displayPacket (packetNb int, packet gopacket.Packet, ethernetPacket *layers.Ethernet, ip *layers.IPv4) {
	fmt.Println("--------------------------------------")
	fmt.Println("Packet n°",packetNb)
	// Get the time when the snapshop was taken
	fmt.Println("Time: ",packet.Metadata().Timestamp)
	// Get the original length of the packet
	fmt.Println("Taille originale: ",packet.Metadata().Length)
	// Get the number of bytes read of the wire
	fmt.Println("Bytes passes: ",packet.Metadata().CaptureLength)
	fmt.Println("----------")
	fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
	fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
	//  Ethernet type is typically IPv4 but could be ARP or other
	fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
	fmt.Println("----------")
	// IP layer variables:
	// Version (Either 4 or 6)
	// IHL (IP Header Length in 32-bit words)
	// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
	// Checksum, SrcIP, DstIP
	fmt.Println("Source IP:", ip.SrcIP)
	fmt.Println("Destination IP: ",ip.DstIP)
	fmt.Println("Protocol: ", ip.Protocol)
	fmt.Println("--------------------------------------")
}



func readConfig(name string) (net.IP, net.IPMask){
	var i int
	var network net.IP
	var mask net.IPMask
	var slash int
	var total int
	i = 0
	file, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// défine the network	
	for scanner.Scan() {
		s_read := scanner.Text()
		switch i {
		case 0:
			network = net.ParseIP(s_read)
		case 1:
			slash, err = strconv.Atoi(s_read)
		case 2:
			total, err = strconv.Atoi(s_read)
		}
		i++
	}
	if (i>=3){
		mask = (net.CIDRMask(slash, total))
	}else{
		log.Fatal(err)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return network, mask
}


func createSnap(packet gopacket.Packet, ip string, mac string)(HostSnapshot){
	var snap HostSnapshot
	// affect the time the snapshot has been taken to the cell of the given IP
	snap.Timestamp = packet.Metadata().Timestamp
	// affect the given MAC to the cell of the given IP
	snap.MacAddress = mac
	// affect the given IP to the cell of the given IP
	snap.IpAddress = ip
	// affect the number of packet count for the transmission by the givetn IP to 1
	snap.Transmission.PacketCount = 1
	// affect the total size of all packet in transmitted in the snapshot to the size of the actual packet (initialize)
	snap.Transmission.TotalSize = int64(packet.Metadata().Length)
	return snap
}

func updateSnap(snap HostSnapshot, packet gopacket.Packet)(HostSnapshot){
	// change the time the snapshot has been taken
	snap.Timestamp = packet.Metadata().Timestamp
	// increase the size of the snapshot (size of all packet receive cumulate) 
	snap.Reception.TotalSize += int64(packet.Metadata().Length)
	// increase the number of packet cumulate in the snapshot
	snap.Reception.PacketCount ++
	return snap
}

func main() {
	var network net.IP
	var mask net.IPMask

	network, mask = readConfig("config")

	// create the map of snapshot
	mapSnap := make(map[string]HostSnapshot)
	
	//  Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	// leave if error
	if err != nil {log.Fatal(err) }
	defer handle.Close()

	// set filter
	//var filter string = "src 172.17"
	//err = handle.SetBPFFilter(filter)
	// leave if error
	//if err != nil {log.Fatal(err) }

	
	// create the stream of packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// initialization of number of packet
	packetNb := 1
	
	// Take every packet of the stream, and do thing
	for packet := range packetSource.Packets() {
		// create the ip var of the packet (containing ip information (layer 3))
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		// create the ethernet var of the packet (containing ethernet information (layer 2))
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		
		// if there are information on the layer 3
		if ipLayer != nil {
			// if there are information on the layer 2
			if ethernetLayer != nil {
				
				// afect to the ip the var of the layers 2 (mac)
				ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
				// affect to the ip the v-ar of IPV4
				ip, _ := ipLayer.(*layers.IPv4)
				// Logic And on the source IP
				srcMasked := ip.SrcIP.Mask(mask)
				// Logic And on the destination IP
				dstMasked := ip.DstIP.Mask(mask)
				if (srcMasked.Equal(network)){// check if the source IP is in the network (defined at the begining)
					if !(dstMasked.Equal(network)){// check if the destination isn't in the network (defined at the begining)
						if snap,ok := mapSnap[ip.SrcIP.String()]; ok {
							/* 
							  check if the map "mapSnap" exist,
							  if not create a map within a structure at the cell named with the source IP
							  and go on the second statement, else go on the first 
							*/
							mapSnap[ip.SrcIP.String()] = updateSnap(snap, packet)
						}else{
							mapSnap[ip.SrcIP.String()] = createSnap(packet, ip.SrcIP.String(), ethernetPacket.SrcMAC.String())
						}
					}
				}else{// if the source IP isn't in the network
					if (dstMasked.Equal(network)){ // if the destination IP is in the network
						if snap,ok := mapSnap[ip.DstIP.String()]; ok {
							/* 
							  check if the map "mapSnap" exist,
							  if not create a map within a structure at the cell named with the destination IP,
							  and go on the second statement, else go on the first 
							*/
							mapSnap[ip.DstIP.String()] = updateSnap(snap, packet)
						}else{	
							mapSnap[ip.DstIP.String()] = createSnap(packet, ip.DstIP.String(), ethernetPacket.DstMAC.String())
						}
					}
				}
				displayPacket(packetNb,packet,ethernetPacket,ip)
				packetNb ++
				if (packetNb % 100 == 0){
					displayAllUsers(mapSnap)
				}
				

			}
			

		}

	}
}

