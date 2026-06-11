package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// reverseDNS returns the first PTR hostname for an IP (without the trailing dot),
// or "" if none. Best-effort; never errors out a scan.
func reverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
}

// ethPARP is the EtherType for ARP.
const ethPARP = 0x0806

// htons converts a uint16 to network byte order.
func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

// buildARPRequest builds a 42-byte Ethernet/ARP "who-has dstIP" broadcast frame.
func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	b := make([]byte, 42)
	// Ethernet header
	copy(b[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // broadcast
	copy(b[6:12], srcMAC)
	binary.BigEndian.PutUint16(b[12:14], ethPARP)
	// ARP payload
	binary.BigEndian.PutUint16(b[14:16], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(b[16:18], 0x0800) // protocol type: IPv4
	b[18] = 6                                    // hardware size
	b[19] = 4                                    // protocol size
	binary.BigEndian.PutUint16(b[20:22], 1)      // opcode: request
	copy(b[22:28], srcMAC)
	copy(b[28:32], srcIP.To4())
	// target hardware address left zero
	copy(b[38:42], dstIP.To4())
	return b
}

// parseARPReply extracts (senderIP, senderMAC) from an ARP reply frame, or
// reports ok=false if the frame is not an ARP reply.
func parseARPReply(frame []byte) (net.IP, net.HardwareAddr, bool) {
	if len(frame) < 42 {
		return nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethPARP {
		return nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[20:22]) != 2 { // opcode: reply
		return nil, nil, false
	}
	mac := net.HardwareAddr(append([]byte(nil), frame[22:28]...))
	ip := net.IP(append([]byte(nil), frame[28:32]...))
	return ip, mac, true
}

// localInterfaceFor finds the up, non-loopback interface (and its IPv4 source
// address) whose subnet contains dstIP. ARP only works on the local segment.
func localInterfaceFor(dstIP net.IP) (*net.Interface, net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for i := range ifaces {
		iface := ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			if ipnet.Contains(dstIP) {
				return &iface, ipnet.IP.To4(), nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no local interface on %s's subnet (ARP only works on the local segment)", dstIP)
}

// ouiVendors maps a MAC OUI prefix (first 3 bytes, upper-case colon form) to a
// vendor. Intentionally a small, common subset - enough for quick LAN triage.
var ouiVendors = map[string]string{
	"00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware", "00:1C:14": "VMware",
	"08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
	"00:15:5D": "Microsoft Hyper-V", "00:03:FF": "Microsoft",
	"00:1A:11": "Google", "3C:5A:B4": "Google",
	"B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
	"00:1B:21": "Intel", "00:1E:67": "Intel", "3C:97:0E": "Intel",
	"00:00:0C": "Cisco", "00:1A:A1": "Cisco", "00:25:45": "Cisco",
	"00:14:22": "Dell", "B0:83:FE": "Dell", "18:03:73": "Dell",
	"00:1F:29": "HP", "3C:D9:2B": "HP", "70:5A:0F": "HP",
	"00:1D:0F": "TP-Link", "50:C7:BF": "TP-Link",
	"00:09:5B": "Netgear", "20:4E:7F": "Netgear",
	"24:A4:3C": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
	"00:03:93": "Apple", "00:CB:00": "Apple", "A4:5E:60": "Apple", "F0:18:98": "Apple",
}

// lookupVendor returns a best-effort vendor name for a MAC, or "" if unknown.
func lookupVendor(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	prefix := fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])
	return ouiVendors[prefix]
}
