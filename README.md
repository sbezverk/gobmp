<p align="left">
  <img src="https://github.com/sbezverk/gobmp/blob/master/Hudson_Go_BMP_logo.png?raw=true" width="40%" height="40%">
</p>

# goBMP

 

goBMP is an implementation of Open BMP (RFC 7854) protocol’s collector in go language.  Collected BGP information can be published to kafka topics, stored in the file in JSON format or printed to stdout.

 

goBMP is suitable to run as a standalone binary as well as a containerized workload, provided deployment yaml allows running it as a deployment in Kubernetes.

 

goBMP receives BGP updates as a part of Open BMP messages, goBMP parses them and generates records depending on BGP Update NLRI and AFI/SAFI.

 

List of currently supported NLRI and AFI/SAFI:

 


<table>
  <tr>
   <td>IPv4 Unicast
   </td>
   <td>1/1
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>IPv4 Labeled Unicast
   </td>
   <td>1/4
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>IPv6 Unicast
   </td>
   <td>2/1
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>IPv6 Labeled Unicast
   </td>
   <td>2/4
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>VPNv4 unicast
   </td>
   <td>1/128
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>VPnv6 unicast
   </td>
   <td>2/128
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Link-state
   </td>
   <td>16388/71
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>L2VPN (VPLS)
   </td>
   <td>25/65
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>L2VPN (EVPN)
   </td>
   <td>25/70
   </td>
   <td>
   </td>
  </tr>
</table>


 

 

goBMP also supports a number of drafts for under development protocols and extensions, such as BGP LS extensions for SRv6 support, Flex Algo, Application Specific attributes etc. 

For the complete list of supported extensions and drafts follow this link: [Support RFCs and Drafts.](https://github.com/sbezverk/gobmp/blob/master/BMP.md)

 

 

The structure of the each record which is published to kafka, stored in the message file or printed to standard output, is defined in the package **_message_** [file types.go](https://github.com/sbezverk/gobmp/blob/master/pkg/message/types.go)

To build goBMP:

git clone [https://github.com/sbezverk/gobmp](https://github.com/sbezverk/gobmp)

cd   gobmp

make gobmp

The linux statically linked binary will be stored in ./bin sub folder.

To run goBMP:

As a binary:

```
./bin/gobmp {list of parameters}
```

*goBMP parameters:*

```
--destination-port={port} (default 5050)
```

When goBMP works in an intercept mode, it receives incoming BMP messages on the source port, makes a copy of BMP message and then transmits the message to the processing listening on a destination port.


```
--dump={file|console}
```

Dump processed BMP messages into a file or to the standard output.


```
--intercept={true|false}
```

When intercept set "true", all incomming BMP messages will be processed and a copy of a message  will be sent to TCP port specified by destination-port.


```
--kafka-server=”kafka server:port”
```

Kafka server TCP/IP address


```
--msg-file={message file path and location} (default "/tmp/messages.json")
```

Full path and  file name to store messages when "dump=file"  


```
--source-port={source-port} (default 5000)
```

Port to listen for incoming BMP messages (default 5000)


```
--v=(1-7)
```

Log level, please use --v=6 for debugging. Level 6 prints in hexadecimal format the incoming message. 

## Docker quick start with RIS Live feed from RIPE

Start gobmp daemon :

```
sudo docker run --net=host sbezverk/gobmp --dump=console
```

Start bgp live feed from RIPE (converted to BMP) :

```
sudo docker run --net=host sbezverk/ris2bmp:1
```

Sample output :

```
gobmp: 06:36:26.088307 {MsgType:7 MsgHash: Msg:{"action":"add","base_attrs":{"base_attr_hash":"c447165a4239db770f610e30dc5df7a7","origin":"igp","as_path":[49697,41047,24961,33891,58453,9808,56048],"as_path_count":7,"nexthop":"80.81.195.241","is_atomic_agg":false,"community_list":"49697:2302, 49697:2500","large_community_list":"24961:1:276, 24961:2:1, 24961:2:150, 24961:2:155, 24961:2:276, 24961:3:1, 24961:4:9002, 24961:5:9002, 24961:6:1, 24961:7:33891, 24961:9:4"},"peer_hash":"75fdb22262697e4b0fcc06f7a8d1496c","peer_ip":"80.81.195.241","peer_asn":49697,"timestamp":"Sep  9 06:34:58.000000","prefix":"223.104.44.0","prefix_len":24,"is_ipv4":true,"origin_as":56048,"nexthop":"80.81.195.241","is_nexthop_ipv4":true,"isprepolicy":false,"is_adj_rib_in":false}}
```

## Status

**goBMP** is work in progress, even though a considerable number of AFI/SAFI and BGP-LS attributes are processed, there is still a lot of work for contribution.
