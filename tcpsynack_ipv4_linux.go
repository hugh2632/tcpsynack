package tcpsynack

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"time"
)

func getFirstValidIp(iplist []net.IP) (res net.IP){
	for _, addr := range iplist {
		res = addr.To4()
		if res != nil {
			break
		}
	}
	return res
}


func IsPortOpen_IPV4_linux(hostname string, port int, timeout int) (bool, error){
	dstaddrs, err := net.LookupIP(hostname)
	if err != nil {
		return false, ErrHostNotFound
	}
	var dstip = getFirstValidIp(dstaddrs)
	if dstip == nil {
		return false, ErrNotIPV4Host
	}
	var dstport = layers.TCPPort(port)

	srcip, sport, err := GetLocalIpPortByDstIP(dstip)
	if err != nil {
		return false, err
	}
	srcport := layers.TCPPort(sport)

	// Ip协议头，用来做校验
	ip := &layers.IPv4{
		SrcIP:    srcip,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}
	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	_ = gopacket.SerializeLayers(buf, opts, tcp)
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false, ErrListenACKFailed
	}
	defer conn.Close()
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		return false, ErrSYNNotSent
	}

	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

	for {
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			return false, ErrReadPacketFailed
		} else if addr.String() == dstip.String() {
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.DstPort == srcport {
					if tcp.SYN && tcp.ACK {
						return true, nil
					}
				}
			}
		} else {
			return false, ErrResponseIPNotMatch
		}
	}
}



