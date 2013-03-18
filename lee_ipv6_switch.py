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

import logging
import struct
from binascii import hexlify
from array import *

#import ryu.lib.ofctl_v1_0
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_str
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import ipv6,ethernet

from ryu.ofproto import nx_match
from ryu.ofproto import ofproto_v1_0_parser
from ryu.lib import mac
from ryu.ofproto import ether
 
LOG = logging.getLogger('ryu.app.simple_switch')

# TODO: we should split the handler into two parts, protocol
# independent and dependant parts.

# TODO: can we use dpkt python library?

# TODO: we need to move the followings to something like db


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        wildcards &= ~ofproto_v1_0.OFPFW_DL_DST

        match = datapath.ofproto_parser.OFPMatch(
            wildcards, in_port, 0, dst,
            0, 0, 0, 0, 0, 0, 0, 0, 0)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def _binary_to_ipv6_format(self,binary):
        
        h = hexlify(binary)
        return [int(h[0:8],16),int(h[8:16],16),int(h[16:24],16),int(h[24:32],16)]
        
    def _to_command(self,table,command):
        return table << 8 | command 

    def  nx_ipv6_add_flow(self,dp,rule,actions):
        command = self._to_command(0, dp.ofproto.OFPFC_ADD)  

        #actions = []
        #actions.append(dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)) 

        _rule = nx_match.ClsRule()
        _rule.set_dl_type(ether.ETH_TYPE_IPV6)

        _rule.set_ipv6_dst(rule.get('ipv6_dst',{}))
        _rule.set_ipv6_src(rule.get('ipv6_src',{}))


        flow_mod = dp.ofproto_parser.NXTFlowMod(datapath=dp,
            cookie=0, command=command, idle_timeout=0, hard_timeout=0,
            priority=0x1, buffer_id=0xffffffff,
            out_port=dp.ofproto.OFPP_NONE,
            flags=0, rule=_rule, actions=actions)
        dp.send_msg(flow_mod)
       
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
       
        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)
        dpid = datapath.id
        print 'mac_to_port',self.mac_to_port,'\n'       
        self.mac_to_port.setdefault(dpid, {})
        print 'mac_to_port',self.mac_to_port,'\n'

        LOG.info("packet in %s %s %s %s",
                 dpid, haddr_to_str(src), haddr_to_str(dst), msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            #self.add_flow(datapath, msg.in_port, dst, [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)])
            self.add_flow(datapath, msg.in_port, dst, actions)        
            #add a ipv6 flow table:        
            if _eth_type == ether.ETH_TYPE_IPV6:
                #print _eth_type
                pkt = Packet(array('B',msg.data))          
                for packet in pkt:
                    if isinstance(packet,array):
                        pass
                    else:
                        if packet.protocol_name=='ipv6':
                            ipv6_packet=packet
                        else:
                            pass
                ipv6_src=self._binary_to_ipv6_format(ipv6_packet.src)
                ipv6_dst=self._binary_to_ipv6_format(ipv6_packet.dst)
                print ipv6_src,ipv6_dst
                '''
                # judge if src and dst addr is special 
                # eg: src [0,0,0,0] dst begin with 0xff01 or 0x ff02 
                if ipv6_src == [0,0,0,0] or ipv6_dst[0]&0xff010000 == 0xff010000 or ipv6_dst[0]&0xff020000 == 0xff020000:
                    print 'ipv6 reserved address\n' 
                #elif ipv6_dst[0]&0xfe800000 == 0xfe800000:
                #    print 'ipv6 dst address is Link-Local address'
                else:
                '''                      
                rule={'ipv6_src':ipv6_src,'ipv6_dst':ipv6_dst}
                self.nx_ipv6_add_flow(datapath,rule,actions)
                print 'add a ipv6 flow entry'  
            
           
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)                 
       
        

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            LOG.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            LOG.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            LOG.info("port modified %s", port_no)
        else:
            LOG.info("Illeagal port state %s %s", port_no, reason)
   
