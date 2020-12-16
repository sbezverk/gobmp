package bgp

const (

	// ECPRouteTarget extended community prefix for for Route Target	[RFC4360]
	ECPRouteTarget = "rt="
	// ECPRouteOrigin extended community prefix for Route Origin	[RFC4360]
	ECPRouteOrigin = "ro="
	// ECPOSPFDomainID extended community prefix for OSPF Domain Identifier	[RFC4577]
	ECPOSPFDomainID = "odi="
	// ECPBGPDataCollection extended community prefix for BGP Data Collection	[RFC4384]
	ECPBGPDataCollection = "bdc="
	// ECPSourceAS extended community prefix for Source AS	[RFC6514]
	ECPSourceAS = "sas="
	// ECPL2VPNID extended community prefix for L2VPN Identifier	[RFC6074]
	ECPL2VPNID = "l2i="
	// ECPCiscoVPNDistinguisher extended community prefix for Cisco VPN-Distinguisher	[Eric_Rosen]
	ECPCiscoVPNDistinguisher = "cvd="
	// ECPRouteTargetRecord extended community prefix for Route-Target Record	[draft-ietf-bess-service-chaining]
	ECPRouteTargetRecord = "rtr="
	// ECPVirtualNetworkID extended community prefix for for Virtual-Network Identifier Extended Community	[Manju_Ramesh]
	ECPVirtualNetworkID = "vni="

	// ECPVRFRouteImport extended community prefix for VRF Route Import	[RFC6514]
	ECPVRFRouteImport = "vri="
	// ECPFlowSpecRedirIPv4 extended community prefix for Flow-spec Redirect to IPv4 [draft-ietf-idr-flowspec-redirect]
	ECPFlowSpecRedirIPv4 = "fsr="
	// ECPInterAreaP2MPSegmentedNexyHop extended community prefix for Inter-Area P2MP Segmented Next-Hop	[RFC7524]
	ECPInterAreaP2MPSegmentedNexyHop = "snh="
	// ECPVRFRecursiveNextHop extended community prefix for VRF-Recursive-Next-Hop-Extended-Community	[Dhananjaya_Rao]
	ECPVRFRecursiveNextHop = "rnh="
	// ECPMVPNSARPAddress  extended community prefix for MVPN SA RP-address Extended Community	[draft-zzhang-bess-mvpn-msdp-sa-interoperation]
	ECPMVPNSARPAddress = "rpa="
	// ECPOSPFRouteID extended community prefix for OSPF Route ID	[RFC4577]
	ECPOSPFRouteID = "ori="

	// ECPGeneric extended community prefix for Generic (deprecated)	[draft-ietf-idr-as4octet-extcomm-generic-subtype]
	ECPGeneric = "deprecated="

	// ECPCost extended community prefix for Cost Community	[draft-ietf-idr-custom-decision]
	ECPCost = "cost="
	// ECPCPORF extended community prefix for CP-ORF	[RFC7543]
	ECPCPORF = "cporf="
	// ECPExtranetSource extended community prefix for Extranet Source Extended Community	[RFC7900]
	ECPExtranetSource = "esrc="

	// ECPExtranetSeparation extended community prefix for Extranet Separation Extended Community	[RFC7900]
	ECPExtranetSeparation = "esep="
	// ECPOSPFRouteType extended community prefix for OSPF Route Type	[RFC4577]
	ECPOSPFRouteType = "ort="
	// ECPAdditionalPMSITunnelAttributeFlags extended community prefix for Additional PMSI Tunnel Attribute Flags	[RFC7902]
	ECPAdditionalPMSITunnelAttributeFlags = "taf="
	// ECPContextLabelSpaceID extended community prefix for Context Label Space ID Extended Community	[draft-ietf-bess-mvpn-evpn-aggregation-label]
	ECPContextLabelSpaceID = "cls="
	// ECPColor extended community prefix for Color Extended Community	[RFC5512]
	ECPColor = "color="
	// ECPEncapsulation extended community prefix for Encapsulation Extended Community	[RFC5512]
	ECPEncapsulation = "encap="
	// ECPDefaultGateway extended community prefix for Default Gateway	[Yakov_Rekhter]
	ECPDefaultGateway = "dg="
	// ECPPointToPointToMultipoint extended community prefix for Point-to-Point-to-Multipoint (PPMP) Label	[Rishabh_Parekh]
	ECPPointToPointToMultipoint = "p2p2m="
	// ECPConsistentHashSortOrder extended community prefix for Consistent Hash Sort Order	[draft-ietf-bess-service-chaining]
	ECPConsistentHashSortOrder = "chso="
	// ECPLoadBalance extended community prefix for LoadBalance	[draft-ietf-bess-service-chaining]
	ECPLoadBalance = "lb="

	// EVPN Extended Community Sub-Types

	// ECPMACMobility extended community prefix for MAC Mobility	[RFC7432]
	ECPMACMobility = "macmob="
	// ECPESILabel extended community prefix for ESI Label	[RFC7432]
	ECPESILabel = "esi-l="
	// ECPESImportRouteTarget extended community prefix for ES-Import Route Target	[RFC7432]
	ECPESImportRouteTarget = "es-irt="
	// ECPEVPNRouterMAC extended community prefix for EVPN Router’s MAC Extended Community	[draft-sajassi-l2vpn-evpn-inter-subnet-forwarding]
	ECPEVPNRouterMAC = "rmac="
	// ECPEVPNLayer2Attributes extended community prefix for EVPN Layer 2 Attributes	[RFC8214]
	ECPEVPNLayer2Attributes = "l2attr="
	// ECPETree extended community prefix for E-Tree Extended Community	[RFC8317]
	ECPETree = "e-tree="
	// ECPDFElection extended community prefix for DF Election Extended Community [RFC8584]
	ECPDFElection = "df-elect="
	// ECPISID extended community prefix for I-SID Extended Community [draft-sajassi-bess-evpn-virtual-eth-segment]
	ECPISID = "i-sid="
	// ECPND extended community prefix for ND Extended Community [draft-snr-bess-evpn-na-flags]
	ECPND = "nd="
	// ECPMulticastFlags extended community prefix for Multicast Flags Extended Community [draft-ietf-bess-evpn-igmp-mld-proxy]
	ECPMulticastFlags = "mflag="
	// ECPEVIRTType0 extended community prefix for EVI-RT Type 0 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]
	ECPEVIRTType0 = "evi-rt0="
	// ECPEVIRTType1 extended community prefix for EVI-RT Type 1 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]
	ECPEVIRTType1 = "evi-rt1="
	// ECPEVIRTType2 extended community prefix for EVI-RT Type 2 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]
	ECPEVIRTType2 = "evi-rt2="
	// ECPEVIRTType3 extended community prefix for EVI-RT Type 3 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]
	ECPEVIRTType3 = "evi-rt3="
	// ECPEVPNAttachmentCircuit extended community prefix for EVPN Attachment Circuit Extended Community [draft-sajassi-bess-evpn-ac-aware-bundling]
	ECPEVPNAttachmentCircuit = "ac="
	// ECPServiceCarvingTimestamp extended community prefix for Service Carving Timestamp [draft-ietf-bess-evpn-fast-df-recovery-01]
	ECPServiceCarvingTimestamp = "sct="

	// Non-Transitive Two-Octet AS-Specific Extended Community Sub-Types

	//ECPLinkBandwidth extended community prefix for Link Bandwidth Extended Community	[draft-ietf-idr-link-bandwidth-00]
	ECPLinkBandwidth = "link-bw="
	// ECPVNIID extended community prefix for Virtual-Network Identifier Extended Community	[draft-drao-bgp-l3vpn-virtual-network-overlays]
	ECPVNIID = "vni="

	// ECPFlowspec extended community prefix for Flowspec extended community
	ECPFlowspec = "flowspec="

	// Flowspec Sub Types

	// CPFlowspecTrafficRate defines Flowspec Traffic rate Sub type
	CPFlowspecTrafficRate = "flowspec-traffic-rate="
	// CPFlowspecTrafficAction defines Flowspec Traffic action Sub type
	CPFlowspecTrafficAction = "flowspec-traffic-action="
	// CPFlowspecRedirect defines Flowspec Redirect Sub type
	CPFlowspecRedirect = "flowspec-redirect="
	// CPFlowspecTrafficRemarking defines Flowspec Traffic Remarking Sub type
	CPFlowspecTrafficRemarking = "flowspec-traffic-remarking="
)
