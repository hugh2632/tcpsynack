package tcpsynack

import (
	"errors"
	"net"
)

var ErrHostNotFound = errors.New("找不到该主机名")
var ErrNotIPV4Host = errors.New("不是IPV4的地址")
var ErrSYNNotSent = errors.New("SYN包未能发送")
var ErrListenACKFailed = errors.New("不能监听ACK")
var ErrLocalEntryNotFound = errors.New("未获取到本地IP和端口")
var ErrReadPacketFailed = errors.New("解析数据包失败")
var ErrResponseIPNotMatch = errors.New("响应报文IP地址不匹配")

// 基于目标地址而获取本地IP和对应的端口
func GetLocalIpPortByDstIP(dstip net.IP) (net.IP, int, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		return nil, -1, err
	}
	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port, nil
		}
	}
	return nil, -1, ErrLocalEntryNotFound
}
