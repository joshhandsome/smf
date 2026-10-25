package context_test

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/free5gc/openapi/models"
	smf_context "github.com/free5gc/smf/internal/context"
	pfcp_message "github.com/free5gc/smf/internal/pfcp/message"
	"github.com/free5gc/smf/internal/pfcp/pfcptype"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/message"
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

// Export actual SMF messages so the UPF's different go-pfcp version can consume
// them. The SMF path is tested even when no export directory is requested.
func TestFramedRouteSubscriptionToPFCPV1(t *testing.T) {
	for _, framed := range []bool{false, true} {
		name := "ordinary"
		if framed {
			name = "framed"
		}
		t.Run(name, func(t *testing.T) {
			sm := newTIPolicyContext(t)
			installDefault(t, sm)
			node := smf_context.NewDataPathNode()
			node.UPF = sm.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode.UPF
			dp := &smf_context.DataPath{FirstDPNode: node}
			sm.PDUAddress = net.ParseIP("10.60.0.10")
			if framed {
				// Actual UDM response JSON, including oneOf and wire field names.
				var subscription models.Udm_SDM_SmSubsData
				require.NoError(t, json.Unmarshal([]byte(`[{"singleNssai":{"sst":1,"sd":"010203"},"dnnConfigurations":{"internet":{"ipv4FrameRouteList":[{"ipv4Mask":"192.168.10.0/24"}]}}}]`), &subscription))
				require.Len(t, subscription.IndividualSmSubsData, 1)
				sm.DnnConfiguration.Ipv4FrameRouteList = subscription.IndividualSmSubsData[0].DnnConfigurations["internet"].Ipv4FrameRouteList
			}
			require.NoError(t, dp.ActivateTunnelAndPDR(sm, 255, smf_context.PathQoSBinding{
				QFI:       sm.SelectedSessionRule().DefQosQFI,
				FlowInfos: []models.Pcf_SMPolCtrl_FlowInformation{{FlowDescription: "permit out ip from 198.18.0.1 to assigned", FlowDirection: models.Pcf_SMPolCtrl_FlowDirectionRm_BIDIRECTIONAL}},
			}))
			t.Cleanup(func() { dp.DeactivateTunnelAndPDR(sm) })
			ul, dl := node.UpLinkTunnel.PDR, node.DownLinkTunnel.PDR
			ul.PDI.LocalFTeid.Teid = 1001
			ul.PDI.LocalFTeid.Ipv4Address = net.ParseIP("127.0.0.8").To4()
			self := smf_context.GetSelf()
			oldNode, oldAddr := self.CPNodeID, self.ExternalAddr
			t.Cleanup(func() { self.CPNodeID, self.ExternalAddr = oldNode, oldAddr })
			self.CPNodeID = pfcptype.NodeID{NodeIdType: pfcptype.NodeIdTypeIpv4Address, IP: net.ParseIP("127.0.0.7").To4()}
			self.ExternalAddr = "127.0.0.7"
			sm.PFCPContext["127.0.0.8"] = &smf_context.PFCPSessionContext{LocalSEID: 41, RemoteSEID: 42}
			pdrs := []*smf_context.PDR{ul, dl}
			fars := []*smf_context.FAR{ul.FAR, dl.FAR}
			qers := append(append([]*smf_context.QER{}, ul.QER...), dl.QER...)
			urrs := append(append([]*smf_context.URR{}, ul.URR...), dl.URR...)
			est, err := pfcp_message.BuildSessionEstablishmentRequest(pfcptype.NodeID{}, "127.0.0.8", "fixture", sm, pdrs, fars, nil, qers, urrs)
			require.NoError(t, err)
			require.Len(t, est.CreatePDR, 2)
			// Simulate the N2 response: downlink forwarding now has the gNB TEID.
			dl.FAR.ForwardingParameters = &smf_context.ForwardingParameters{
				DestinationInterface: pfcptype.DestinationInterface{InterfaceValue: pfcptype.DestinationInterfaceAccess},
				OuterHeaderCreation:  &pfcptype.OuterHeaderCreation{OuterHeaderCreationDescription: 0x0100, Teid: 2001, Ipv4Address: net.ParseIP("127.0.0.9").To4()},
			}
			dl.FAR.ApplyAction = pfcptype.ApplyAction{Forw: true}
			dl.FAR.State = smf_context.RULE_UPDATE
			for _, pdr := range pdrs {
				pdr.State = smf_context.RULE_UPDATE
			}
			mod, err := pfcp_message.BuildSessionModificationRequest("127.0.0.8", "fixture", sm, pdrs, []*smf_context.FAR{dl.FAR}, nil, nil, nil)
			require.NoError(t, err)
			require.Len(t, mod.UpdatePDR, 2)
			for suffix, msg := range map[string]message.Message{"est": est, "mod": mod} {
				wire := make([]byte, msg.MarshalLen())
				require.NoError(t, msg.MarshalTo(wire))
				_, err = message.Parse(wire)
				require.NoError(t, err)
				if dir := os.Getenv("FRAMED_ROUTE_FIXTURES"); dir != "" {
					require.NoError(t, os.MkdirAll(dir, 0755))
					require.NoError(t, os.WriteFile(filepath.Join(dir, name+"-"+suffix+".pfcp"), wire, 0644))
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
