package context_test

import (
	"testing"

	"github.com/free5gc/openapi/models"
	smf_context "github.com/free5gc/smf/internal/context"
	"github.com/stretchr/testify/require"
)

func TestFramedRouteActivationV1(t *testing.T) {
	for _, prefix := range []string{"", "192.168.10.11/24"} {
		t.Run(prefix, func(t *testing.T) {
			sm := newTIPolicyContext(t)
			installDefault(t, sm)
			node := smf_context.NewDataPathNode()
			node.UPF = sm.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode.UPF
			dp := &smf_context.DataPath{FirstDPNode: node}
			if prefix != "" {
				sm.DnnConfiguration.Ipv4FrameRouteList = []models.Udm_SDM_FrameRouteInfo{{Ipv4Mask: prefix}}
			}
			require.NoError(t, dp.ActivateTunnelAndPDR(sm, 255,
				smf_context.PathQoSBinding{QFI: sm.SelectedSessionRule().DefQosQFI}))
			t.Cleanup(func() { dp.DeactivateTunnelAndPDR(sm) })
			require.Nil(t, dp.FirstDPNode.Next())
			for _, tunnel := range []*smf_context.GTPTunnel{dp.FirstDPNode.UpLinkTunnel, dp.FirstDPNode.DownLinkTunnel} {
				require.NotNil(t, tunnel.PDR.PDI.UEIPAddress)
				if prefix == "" {
					require.Empty(t, tunnel.PDR.PDI.FramedRoutes)
				} else {
					require.Equal(t, []string{"192.168.10.0/24"}, tunnel.PDR.PDI.FramedRoutes)
				}
			}
		})
	}
}

func TestFramedRouteRejectsBeforeAllocationV1(t *testing.T) {
	for _, prefix := range []string{"bad", "", "0.0.0.0/0", "2001:db8::/64", "127.0.0.0/8", "224.0.0.0/4"} {
		t.Run(prefix, func(t *testing.T) {
			sm := newTIPolicyContext(t)
			installDefault(t, sm)
			node := smf_context.NewDataPathNode()
			node.UPF = sm.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode.UPF
			dp := &smf_context.DataPath{FirstDPNode: node}
			sm.DnnConfiguration.Ipv4FrameRouteList = []models.Udm_SDM_FrameRouteInfo{{Ipv4Mask: prefix}}
			err := dp.ActivateTunnelAndPDR(sm, 255, smf_context.PathQoSBinding{QFI: sm.SelectedSessionRule().DefQosQFI})
			require.Error(t, err)
			require.False(t, dp.Activated)
			require.Nil(t, dp.FirstDPNode.UpLinkTunnel.PDR)
		})
	}
}
