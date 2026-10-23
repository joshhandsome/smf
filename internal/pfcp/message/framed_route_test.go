package message

import (
	"net"
	"testing"

	"github.com/free5gc/smf/internal/context"
	"github.com/free5gc/smf/internal/pfcp/pfcptype"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
)

func TestFramedRouteCreateAndUpdateWireV1(t *testing.T) {
	for _, routes := range [][]string{nil, {"192.168.10.0/24"}} {
		pdr := &context.PDR{PDRID: 1, FAR: &context.FAR{FARID: 2}, PDI: context.PDI{
			UEIPAddress:  &pfcptype.UEIPAddress{V4: true, Ipv4Address: net.ParseIP("10.60.0.10").To4()},
			FramedRoutes: routes,
		}}
		for _, build := range []func(*context.PDR) (*ie.IE, error){newCreatePDRIE, newUpdatePDRIE} {
			group, err := build(pdr)
			require.NoError(t, err)
			wire := make([]byte, group.MarshalLen())
			require.NoError(t, group.MarshalTo(wire))
			decoded, err := ie.Parse(wire)
			require.NoError(t, err)
			var children []*ie.IE
			if decoded.Type == ie.CreatePDR {
				children, err = decoded.CreatePDR()
			} else {
				children, err = decoded.UpdatePDR()
			}
			require.NoError(t, err)
			found, ueFound := 0, false
			for _, child := range children {
				if child.Type != ie.PDI {
					continue
				}
				pdi, err := child.PDI()
				require.NoError(t, err)
				for _, item := range pdi {
					if item.Type == ie.UEIPAddress {
						ueFound = true
					}
					if item.Type == ie.FramedRoute {
						value, err := item.FramedRoute()
						require.NoError(t, err)
						require.Equal(t, "192.168.10.0/24 0.0.0.0 1", value)
						found++
					}
				}
			}
			require.True(t, ueFound)
			require.Equal(t, len(routes), found)
		}
	}
}
