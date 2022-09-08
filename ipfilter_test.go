package ipfilter_test

import (
	"net"
	"testing"

	"github.com/runner-mei/ipfilter"
	"github.com/stretchr/testify/assert"
)

const (
	egUS = "52.92.180.128"
	egAU = "49.189.50.1"
	egCN = "116.31.116.51"
)

func TestSingleIP(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockByDefault: true,
	})
	assert.True(t, f.Allowed("222.25.118.1"), "[1] should be allowed")
	assert.True(t, f.Blocked("222.25.118.2"), "[2] should be blocked")
	assert.True(t, f.NetAllowed(net.IP{222, 25, 118, 1}), "[3] should be allowed")
	assert.True(t, f.NetBlocked(net.IP{222, 25, 118, 2}), "[4] should be blocked")
}

func TestSubnetIP(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"10.0.0.0/16"},
		BlockByDefault: true,
	})
	assert.True(t, f.Allowed("10.0.0.1"), "[1] should be allowed")
	assert.True(t, f.Allowed("10.0.42.1"), "[2] should be allowed")
	assert.True(t, f.Blocked("10.42.0.1"), "[3] should be blocked")
}