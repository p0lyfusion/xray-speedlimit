package netif

import (
	"strings"
	"testing"
)

const routeHeader = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

func TestDefaultRouteInterface(t *testing.T) {
	cases := []struct {
		name  string
		table string
		want  string
	}{
		{
			name: "plain default route",
			table: "eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" +
				"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "split-default /1 route listed first is not the default route",
			table: "tun0\t00000000\t0100080A\t0003\t0\t0\t0\t00000080\t0\t0\t0\n" +
				"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "lowest metric wins",
			table: "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
				"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "route that isn't up is skipped",
			table: "eth1\t00000000\t0103A8C0\t0002\t0\t0\t0\t00000000\t0\t0\t0\n" +
				"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
	}
	for _, tc := range cases {
		got, err := defaultRouteInterface(strings.NewReader(routeHeader + tc.table))
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDefaultRouteInterfaceNone(t *testing.T) {
	table := routeHeader + "eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	if got, err := defaultRouteInterface(strings.NewReader(table)); err == nil {
		t.Fatalf("expected an error with no default route, got %q", got)
	}
}
