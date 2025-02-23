package lib

import (
	"log"
	"net"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ScanNetwork(ipRange, localIP, gatewayIP string) []Device {
	var devices []Device
	var whitelist []Whitelist
	LoadFromJSON(
		"ip_whitelist.json",
		&whitelist,
	)

	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	for i := 0; i < 3; i++ {
		arpRequest := createARPPacket(ipRange)
		err = handle.WritePacketData(arpRequest)
		if err != nil {
			log.Fatal(err)
		}

		start := time.Now()
		for time.Since(start) < 4*time.Second {
			data, _, err := handle.ReadPacketData()
			if err != nil {
				continue
			}
			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)
				ip := net.IP(arp.SourceProtAddress).String()
				mac := net.HardwareAddr(arp.SourceHwAddress).String()
				containsIP := false
				for _, w := range whitelist {
					if w.Contains(ip) {
						containsIP = true
						break
					}
				}
				if ip != localIP && ip != gatewayIP && !containsIP {
					if !containsDevice(devices, ip) {
						host, _ := net.LookupAddr(ip)
						devices = append(devices, Device{IP: ip, MAC: mac, Host: host[0]})
					}
				}
			}
		}
	}

	sort.Slice(devices, func(i, j int) bool {
		return devices[i].IP < devices[j].IP
	})

	SaveToJSON("network_devices.json", devices)
	return devices
}

func createARPPacket(ipRange string) []byte {
	ethLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x0c, 0x29, 0x4f, 0x8e, 0x35},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte{0x00, 0x0c, 0x29, 0x4f, 0x8e, 0x35},
		SourceProtAddress: net.ParseIP("192.168.1.1").To4(),
		DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    net.ParseIP(ipRange).To4(),
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, ethLayer, arpLayer)
	if err != nil {
		log.Fatal(err)
	}

	return buffer.Bytes()
}

func (w *Whitelist) Contains(ip string) bool {
	for _, whitelistIP := range w.IPs {
		if whitelistIP == ip {
			return true
		}
	}
	return false
}

func containsDevice(devices []Device, ip string) bool {
	for _, device := range devices {
		if device.IP == ip {
			return true
		}
	}
	return false
}
