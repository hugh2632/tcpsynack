package tcpsynack

import "testing"

func TestIsPortOpen_IPV4_linux(t *testing.T) {
	opened, err := IsPortOpen_IPV4_linux("www.baidu.com", 80, 100)
	if err != nil {
		t.Log(err)
	}
	t.Log(opened)
}
