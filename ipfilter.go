package ipfilter

import (
	"io/ioutil"
	"log"
	"net"
	"net/http"

	// "github.com/phuslu/iploc"
	"github.com/tomasen/realip"
)

//Options for IPFilter. Allow supercedes Block for IP checks
//across all matching subnets, whereas country checks use the
//latest Allow/Block setting.
//IPs can be IPv4 or IPv6 and can optionally contain subnet
//masks (e.g. /24). Note however, determining if a given IP is
//included in a subnet requires a linear scan so is less performant
//than looking up single IPs.
//
//This could be improved with cidr range prefix tree.
type Options struct {
	//explicity allowed IPs
	AllowedIPs []string
	//explicity blocked IPs
	BlockedIPs []string

	//block by default (defaults to allow)
	BlockByDefault bool
	// TrustProxy enable check request IP from proxy
	TrustProxy bool
	// Logger enables logging, printing using the provided interface
	Logger interface {
		Printf(format string, v ...interface{})
	}
}

type IPFilter struct {
	opts Options
	defaultAllowed bool
	ips            map[string]bool
	subnets        []*subnet
}

type subnet struct {
	str     string
	ipnet   *net.IPNet
	allowed bool
}

//New constructs IPFilter instance without downloading DB.
func New(opts Options) *IPFilter {
	if opts.Logger == nil {
		//disable logging by default
		opts.Logger = log.New(ioutil.Discard, "", 0)
	}
	f := &IPFilter{
		opts:           opts,
		ips:            map[string]bool{},
		defaultAllowed: !opts.BlockByDefault,
	}
	for _, ip := range opts.BlockedIPs {
		f.blockIP(ip)
	}
	for _, ip := range opts.AllowedIPs {
		f.allowIP(ip)
	}
	return f
}

func (f *IPFilter) printf(format string, args ...interface{}) {
	if l := f.opts.Logger; l != nil {
		l.Printf("[ipfilter] "+format, args...)
	}
}

func (f *IPFilter) allowIP(ip string) bool {
	return f.toggleIP(ip, true)
}

func (f *IPFilter) blockIP(ip string) bool {
	return f.toggleIP(ip, false)
}

func (f *IPFilter) toggleIP(str string, allowed bool) bool {
	//check if has subnet
	if ip, net, err := net.ParseCIDR(str); err == nil {
		// containing only one ip? (no bits masked)
		if n, total := net.Mask.Size(); n == total {
			f.ips[ip.String()] = allowed
			return true
		}

		found := false
		for _, subnet := range f.subnets {
			if subnet.str == str {
				found = true
				subnet.allowed = allowed
				break
			}
		}
		if !found {
			f.subnets = append(f.subnets, &subnet{
				str:     str,
				ipnet:   net,
				allowed: allowed,
			})
		}
		return true
	}
	//check if plain ip (/32)
	if ip := net.ParseIP(str); ip != nil {
		f.ips[ip.String()] = allowed
		return true
	}
	return false
}


//ToggleDefault alters the default setting
func (f *IPFilter) ToggleDefault(allowed bool) {
	f.defaultAllowed = allowed
}

//Allowed returns if a given IP can pass through the filter
func (f *IPFilter) Allowed(ipstr string) bool {
	return f.NetAllowed(net.ParseIP(ipstr))
}

//NetAllowed returns if a given net.IP can pass through the filter
func (f *IPFilter) NetAllowed(ip net.IP) bool {
	//invalid ip
	if ip == nil {
		return false
	}

	//check single ips
	allowed, ok := f.ips[ip.String()]
	if ok {
		return allowed
	}
	//scan subnets for any allow/block
	blocked := false
	for _, subnet := range f.subnets {
		if subnet.ipnet.Contains(ip) {
			if subnet.allowed {
				return true
			}
			blocked = true
		}
	}
	if blocked {
		return false
	}
	//use default setting
	return f.defaultAllowed
}

//Blocked returns if a given IP can NOT pass through the filter
func (f *IPFilter) Blocked(ip string) bool {
	return !f.Allowed(ip)
}

//NetBlocked returns if a given net.IP can NOT pass through the filter
func (f *IPFilter) NetBlocked(ip net.IP) bool {
	return !f.NetAllowed(ip)
}

//Wrap the provided handler with simple IP blocking middleware
//using this IP filter and its configuration
func (f *IPFilter) Wrap(next http.Handler) http.Handler {
	return &ipFilterMiddleware{IPFilter: f, next: next}
}

//Wrap is equivalent to NewLazy(opts) then Wrap(next)
func Wrap(next http.Handler, opts Options) http.Handler {
	if len(opts.AllowedIPs) == 0 && len(opts.BlockedIPs) == 0 && !opts.BlockByDefault {
		return next
	}
	return New(opts).Wrap(next)
}

type ipFilterMiddleware struct {
	*IPFilter
	next http.Handler
}

func (m *ipFilterMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var remoteIP string
	if m.opts.TrustProxy {
		remoteIP = realip.FromRequest(r)
	} else {
		remoteIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	if remoteIP != "127.0.0.1" && remoteIP != "::1" {
		allowed := m.IPFilter.Allowed(remoteIP)
		if !allowed {
			//show simple forbidden text
			m.printf("blocked %s", remoteIP)
			http.Error(w, "", http.StatusForbidden)
			return
		}
	}
	//success!
	m.next.ServeHTTP(w, r)
}

//NewNoDB is the same as New
func NewNoDB(opts Options) *IPFilter {
	return New(opts)
}

//NewLazy is the same as New
func NewLazy(opts Options) *IPFilter {
	return New(opts)
}