# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.lib.packet import udp

"""
fill in the code here for any used constant (optional)
"""

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        #nat logic variables
        self.nat_to_port = {}
        self.counter_port = 50001

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath_id

        self.logger.info("Datapath ID is %s", hex(dpid))

        if dpid == 0x1A:
            out_port = 4 #low-delay port
                
            actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:05:01")]
            actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:05:02"))
                    
            match = datapath.ofproto_parser.OFPMatch(dl_type = 0x800,nw_tos=8,
                                            nw_dst="192.168.2.1", nw_dst_mask=24)
      
            actions.append(datapath.ofproto_parser.OFPActionOutput(out_port,0))
                    
            self.add_flow(datapath,match,actions)
        
        elif dpid == 0x1B:
            out_port = 4 #low-delay port

            actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:05:02")]
            actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:05:01"))
                    
            match = datapath.ofproto_parser.OFPMatch(dl_type = 0x800,nw_tos=8,
                                    nw_dst="192.168.1.1", nw_dst_mask=24)
                    
            actions.append(datapath.ofproto_parser.OFPActionOutput(out_port,0))
                    
            self.add_flow(datapath,match,actions)

            out_port = 1 #udp-traffic-port

            actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:02")]
            actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:01"))
                    
            match = datapath.ofproto_parser.OFPMatch(dl_type = 0x800,nw_proto=17,
                                    nw_dst="200.0.0.0", nw_dst_mask=24)
                    
            actions.append(datapath.ofproto_parser.OFPActionOutput(out_port,0))
                    
            self.add_flow(datapath,match,actions)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        self.logger.info("packet in %s %s %s %s %s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        if dpid == 0x2 or dpid == 0x3:
            self.mac_to_port.setdefault(dpid, {})

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = msg.in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            match = datapath.ofproto_parser.OFPMatch(
                in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, match, actions)
            
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)
            return

        if dpid == 0x1A:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arp_packet = pkt.get_protocol(arp.arp)

                if arp_packet.opcode == 1:
                    if arp_packet.dst_ip == "192.168.1.1" or arp_packet.dst_ip == "200.0.0.1":
                        self.reply_arp(msg.in_port,datapath,arp_packet)
                        return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                ip_packet = pkt.get_protocol(ipv4.ipv4)

                self.packet_forwarding(msg.in_port,datapath,ip_packet,eth,msg.data,msg)
                return
            return
        if dpid == 0x1B:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arp_packet = pkt.get_protocol(arp.arp)

                if arp_packet.opcode == 1:
                    if arp_packet.dst_ip == "192.168.2.1":
                        self.reply_arp(msg.in_port,datapath,arp_packet)
                        return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                ip_packet = pkt.get_protocol(ipv4.ipv4)

                self.packet_forwarding(msg.in_port,datapath,ip_packet,eth,msg.data,msg)
                return
            return

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)


    
    def reply_arp(self,in_port,datapath,arp_packet):

        self.logger.info("Packet request from Mac = %s, IP = %s to MAC = %s IP = %s",arp_packet.src_mac,arp_packet.src_ip,arp_packet.dst_mac,arp_packet.dst_ip)

        if arp_packet.dst_ip == "192.168.1.1":
            e = ethernet.ethernet(arp_packet.src_mac,"00:00:00:00:01:01",ether_types.ETH_TYPE_ARP)
            a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                   src_mac="00:00:00:00:01:01",src_ip=arp_packet.dst_ip,dst_mac=arp_packet.src_mac,dst_ip=arp_packet.src_ip)
        elif arp_packet.dst_ip == "192.168.2.1":
            e = ethernet.ethernet(arp_packet.src_mac,"00:00:00:00:02:01",ether_types.ETH_TYPE_ARP)
            a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                   src_mac="00:00:00:00:02:01",src_ip=arp_packet.dst_ip,dst_mac=arp_packet.src_mac,dst_ip=arp_packet.src_ip)
        elif arp_packet.dst_ip == "200.0.0.1":
            e = ethernet.ethernet(arp_packet.src_mac,"00:00:00:00:04:01",ether_types.ETH_TYPE_ARP)
            a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                   src_mac="00:00:00:00:04:01",src_ip=arp_packet.dst_ip,dst_mac=arp_packet.src_mac,dst_ip=arp_packet.src_ip)

        self.logger.info("Packet reply to Mac = %s, IP = %s from MAC = %s IP = %s",a.dst_mac,a.dst_ip,a.src_mac,a.src_ip)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(in_port,0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    def packet_forwarding(self,in_port,datapath,ip_packet,eth,data,msg):
        if datapath.id == 0x1A:
            if "200.0.0." in ip_packet.dst and ip_packet.proto == 17:
                pkt = packet.Packet(msg.data)
                udp_packet = pkt.get_protocol(udp.udp)

                if ip_packet.dst == "200.0.0.2":
                    check_match = {"src_port":udp_packet.src_port,"src_ip":ip_packet.src,"dst_port":udp_packet.dst_port,"dst_ip":ip_packet.dst}


                    #controller may receive more packets for the first time due to iperf so
                    #by this code handling the problem of duplicate packets
                    #and is implemented the nat logic.
                    if check_match not in self.nat_to_port.values():
                        self.nat_to_port.setdefault(self.counter_port,{"src_port":udp_packet.src_port,"src_ip":ip_packet.src,
                                                                                "dst_port":udp_packet.dst_port,"dst_ip":ip_packet.dst})
                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:04:01")]
                        actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:04:02"))
                        actions.append(datapath.ofproto_parser.OFPActionSetNwSrc("200.0.0.1"))
                        actions.append(datapath.ofproto_parser.OFPActionSetTpSrc(self.counter_port))

                        out_port = 3
                        
                        match = datapath.ofproto_parser.OFPMatch(dl_type = 0x800,nw_tos=0,nw_proto=17,
                                                                nw_src=ip_packet.src,tp_src=udp_packet.src_port,
                                                                nw_dst= "200.0.0.2",tp_dst=udp_packet.dst_port)

                        actions.append(datapath.ofproto_parser.OFPActionOutput(out_port,0))
                        self.add_flow(datapath, match, actions)
                        out = datapath.ofproto_parser.OFPPacketOut(
                                                datapath=datapath,
                                                buffer_id=0xffffffff,
                                                in_port=datapath.ofproto.OFPP_CONTROLLER,
                                                actions=actions,
                                                data=data)
                        datapath.send_msg(out)

                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(eth.dst)]
                        actions.append(datapath.ofproto_parser.OFPActionSetDlDst(eth.src))
                        actions.append(datapath.ofproto_parser.OFPActionSetNwDst(ip_packet.src))
                        actions.append(datapath.ofproto_parser.OFPActionSetTpDst(udp_packet.src_port))
                        
                        if "192.168.1" in ip_packet.src:
                            out_port = 2
                        elif "192.168.2" in ip_packet.src:
                            out_port = 1

                        match = datapath.ofproto_parser.OFPMatch(dl_type = 0x800,nw_tos=0,nw_proto=17,
                                                                tp_dst=self.counter_port,nw_dst= "200.0.0.1")

                        actions.append(datapath.ofproto_parser.OFPActionOutput(out_port,0))
                        self.add_flow(datapath, match, actions)

                        self.counter_port +=1
                return
        #icmp
        if ("192.168.1" not in ip_packet.dst) and ("192.168.2" not in ip_packet.dst):
            if "192.168.1" in ip_packet.src:
                source = "192.168.1.1"
                out_port = 2
            elif "192.168.2" in ip_packet.src:
                source = "192.168.2.1"
                out_port = 2
            else:
                source = "200.0.0.1"
                out_port = 3
            
            e = ethernet.ethernet(eth.src,eth.dst,2048)
            ip = ipv4.ipv4(proto=1,src=source,dst=ip_packet.src)
            icmp_packet = icmp.icmp(type_=3,code=1,csum=0,data=icmp.dest_unreach(data=msg.data[ethernet.ethernet._MIN_LEN:]))

            p = packet.Packet()
            p.add_protocol(e)
            p.add_protocol(ip)
            p.add_protocol(icmp_packet)
            p.serialize()
            

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port,0)]
            out = datapath.ofproto_parser.OFPPacketOut(
                                        datapath=datapath,
                                        buffer_id=0xffffffff,
                                        in_port=datapath.ofproto.OFPP_CONTROLLER,
                                        actions=actions,
                                        data=p.data)
            datapath.send_msg(out)
            return
        if "192.168.2." in ip_packet.dst:
            self.logger.info(datapath.id)
            #if eth.dst != "00:00:00:00:03:02":
            if datapath.id == 0x1A:
               actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:01")]
               actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:02"))
               
               match = datapath.ofproto_parser.OFPMatch(dl_type = 0x800,nw_tos=0,
                                    nw_dst= "192.168.2.1", nw_dst_mask=24)
               out_port = 1
               actions.append(datapath.ofproto_parser.OFPActionOutput(out_port,0))
               self.add_flow(datapath, match, actions)
            else: 
               actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:02:01")] 
               out_port = 2
               if ip_packet.dst == "192.168.2.2":
                   actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:02:02"))
                   
                   match = datapath.ofproto_parser.OFPMatch(dl_type = 0x800,nw_tos=0,
                                                    nw_dst= "192.168.2.2")
                   actions.append(datapath.ofproto_parser.OFPActionOutput(out_port,0))
                   self.add_flow(datapath, match, actions)
               else:
                   actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:02:03"))
                   
                   match = datapath.ofproto_parser.OFPMatch(dl_type = 0x800,nw_tos=0,
                                            nw_dst= "192.168.2.3")
                   actions.append(datapath.ofproto_parser.OFPActionOutput(out_port,0))
                   self.add_flow(datapath, match, actions)
        elif "192.168.1." in ip_packet.dst:
            #if eth.dst != "00:00:00:00:03:01":
            if datapath.id == 0x1B:
               actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:02")]
               actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:01"))
               
               match = datapath.ofproto_parser.OFPMatch(dl_type = 0x800,nw_tos=0,
                                    nw_dst= "192.168.1.1", nw_dst_mask=24)
               out_port = 1
               actions.append(datapath.ofproto_parser.OFPActionOutput(out_port,0))
               self.add_flow(datapath, match, actions)
            else:
               actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:01:01")]
               out_port = 2
               if ip_packet.dst == "192.168.1.2":
                   actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:01:02"))
                   
                   match = datapath.ofproto_parser.OFPMatch(dl_type=0x800,nw_tos=0,
                                        nw_dst = "192.168.1.2")
                   actions.append(datapath.ofproto_parser.OFPActionOutput(out_port,0))
                   self.add_flow(datapath, match, actions)
               else:
                   actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:01:03"))
                   
                   match = datapath.ofproto_parser.OFPMatch(dl_type = 0x800,nw_tos=0,
                                        nw_dst = "192.168.1.3")
                   actions.append(datapath.ofproto_parser.OFPActionOutput(out_port,0))
                   self.add_flow(datapath, match, actions)
        out = datapath.ofproto_parser.OFPPacketOut(
                            datapath=datapath,
                            buffer_id=0xffffffff,
                            in_port=datapath.ofproto.OFPP_CONTROLLER,
                            actions=actions,
                            data=data)
        datapath.send_msg(out)
