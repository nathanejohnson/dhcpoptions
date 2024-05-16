package commands

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/mitchellh/cli"
)

type routeArg struct {
	ipnet net.IPNet
	route net.IP
}

func (ra *routeArg) encode() string {
	var b [18]byte

	routeIP := ra.route.To4()
	if routeIP == nil {
		return ""
	}

	maskIP := ra.ipnet.IP.To4()
	if maskIP == nil {
		return ""
	}
	ones, _ := ra.ipnet.Mask.Size()
	if ones > 32 {
		return ""
	}
	sigs := sigBytes(ones)
	hex.Encode(b[0:2], []byte{byte(ones)})
	maskEnd := sigs*2 + 2
	hex.Encode(b[2:maskEnd], maskIP[:sigs])
	routeEnd := maskEnd + 8
	hex.Encode(b[maskEnd:routeEnd], routeIP)
	return string(b[:routeEnd])
}

func routeArgsFromHex(s string) ([]routeArg, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.Trim(s, ":")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) < 5 {
		return nil, fmt.Errorf("hex too short")
	}
	var ras []routeArg
	for len(b) >= 5 {
		var ra routeArg
		ones := int(b[0])
		if ones > 32 {
			return nil, fmt.Errorf("mask too large")
		}
		sigs := sigBytes(ones)
		ra.ipnet.IP = make([]byte, 4)

		if len(b) < 5+sigs {
			return nil, fmt.Errorf("invalid length")
		}
		ra.route = make([]byte, 4)
		copy(ra.route, b[1+sigs:5+sigs])
		ra.ipnet.Mask = net.CIDRMask(ones, 32)
		copy(ra.ipnet.IP, b[1:1+sigs])
		ras = append(ras, ra)
		b = b[5+sigs:]
	}

	return ras, nil
}

func sigBytes(ones int) int {
	return (ones + 7) >> 3
}

type routeArgs []routeArg

func (ras routeArgs) String() string {
	var sb strings.Builder
	if len(ras) > 0 {
		sb.WriteString("0x")
	}
	for _, ra := range ras {
		sb.WriteString(ra.encode())
	}
	return sb.String()
}

func (ras *routeArgs) Set(s string) error {
	pieces := strings.SplitN(s, ",", 2)
	if len(pieces) == 0 {
		return errors.New("invalid route arguments")
	}
	var ipnet *net.IPNet
	var ip net.IP
	if len(pieces) == 1 {
		// classful - we only have an ip to route to, infer
		// subnet from class
		ip = net.ParseIP(pieces[0])
		if ip == nil {
			return errors.New("could not parse IP")
		}
		ip = ip.To4()
		if ip == nil {
			return errors.New("IP is not ipv4")
		}
		ra := routeArg{
			route: ip,
			ipnet: net.IPNet{IP: make([]byte, 4), Mask: net.CIDRMask(0, 32)},
		}
		*ras = append(*ras, ra)
		return nil
	}
	_, ipnet, err := net.ParseCIDR(pieces[0])
	if err != nil {
		return err
	}
	_, size := ipnet.Mask.Size()
	if size != 32 {
		return errors.New("invalid route arguments - net must be ipv4")
	}
	ip = net.ParseIP(pieces[1])
	if ip == nil {
		return errors.New("invalid ip address")
	}
	ip = ip.To4()
	if ip == nil {
		return errors.New("ipv6 not supported")
	}
	*ras = append(*ras, routeArg{
		ipnet: *ipnet,
		route: ip,
	})
	return nil
}

func NewOption121Cmd() *Option121Cmd {
	fs := flag.NewFlagSet("option121", flag.ContinueOnError)
	o := &Option121Cmd{
		fs: fs,
	}
	fs.Var(&o.routeArgs, "route-arg", "add route argument as "+
		"'network/cidr,route'.  like -route-arg='192.168.0.0/16,192.168.1.1' multiple allowed")

	fs.StringVar(&o.encodedArg, "encoded-arg", "", "hex encoded 121 option to decode")

	return o
}

type Option121Cmd struct {
	fs         *flag.FlagSet
	routeArgs  routeArgs
	encodedArg string
}

func (o *Option121Cmd) Help() string {
	var buff bytes.Buffer
	o.fs.SetOutput(&buff)
	o.fs.Usage()
	return buff.String()
}

func (o *Option121Cmd) Run(args []string) int {
	err := o.fs.Parse(args)
	if err != nil {
		return cli.RunResultHelp
	}
	if (len(o.routeArgs) == 0) == (len(o.encodedArg) == 0) {
		log.Printf("must choose either of route-args or encoded-args, but not both")
		return cli.RunResultHelp
	}

	switch {
	case len(o.routeArgs) > 0:
		fmt.Printf("option 121 val: %s\n", o.routeArgs.String())
	default:
		ras, err := routeArgsFromHex(o.encodedArg)
		if err != nil {
			log.Fatalf("fuck: %s", err)
		}
		for _, ra := range ras {
			fmt.Printf("net: %s -> %s\n", ra.ipnet.String(), ra.route)
		}
	}
	return 0
}

func (o *Option121Cmd) Synopsis() string {
	return "format and parse dhcp option 121 arguments"
}
