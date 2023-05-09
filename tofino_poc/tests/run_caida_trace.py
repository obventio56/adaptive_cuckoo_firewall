#  This file was adapted from a tofino test example. Original license is below:
#
################################################################################
#
#  INTEL CONFIDENTIAL
#
#  Copyright (c) 2021 Intel Corporation
#  All Rights Reserved.
#
#  This software and the related documents are Intel copyrighted materials,
#  and your use of them is governed by the express license under which they
#  were provided to you ("License"). Unless the License provides otherwise,
#  you may not use, modify, copy, publish, distribute, disclose or transmit this
#  software or the related documents without Intel's prior written permission.
#
#  This software and the related documents are provided as is, with no express or
#  implied warranties, other than those that are expressly stated in the License.
#################################################################################

import struct
import struct
from scapy.all import *
from scapy.layers.all import Ether, IP, TCP, Padding

import ptf.testutils as testutils
from p4testutils.misc_utils import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import importlib.util
import sys
import os

REPO_PATH = '/home/alex'

def load_module(file_name, module_name):
    spec = importlib.util.spec_from_file_location(module_name, file_name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

utils = load_module(REPO_PATH + "/tofino_acf_firewall/tofino_poc/util.py", "utils")
ACF = load_module(REPO_PATH + "/tofino_acf_firewall/ACF.py", "ACF")

p4_program_name = "src"

logger = get_logger()
swports = get_sw_ports()

# A/S ratio (Michael's sec4.2 experiment)
gfp_count = 0
trace_complete = False

""" Helper function to pack five tuple into a byte string with C struct format so that python CRC matches Tofino CRC"""
def packFiveTuple(fiveTuple):
    src_addr, dst_addr, src_port, dst_port, protocol = fiveTuple
    return struct.pack("!IIHHB", int.from_bytes(socket.inet_aton(src_addr), "big"), int.from_bytes(socket.inet_aton(dst_addr), "big"), src_port,  dst_port, protocol)

""" A class of abstractions for interacting with register arrays
"""
class RegisterArray():
    def __init__(self, interface, p4Name, regArrayName):
        self.val_field = "val"
        self.regArrayName = regArrayName
        self.bfrt_info = interface.bfrt_info_get(p4Name)
        self.register_table = self.bfrt_info.table_get(regArrayName)
        self.target = gc.Target(device_id=0, pipe_id=0xffff)

    def readIndex(self, index):
        resp = self.register_table.entry_get(
            self.target,
            [self.register_table.make_key(
                [gc.KeyTuple('$REGISTER_INDEX', index)])],
            {"from_hw": False})
        data, _ = next(resp)
        data_dict = data.to_dict()
        return data_dict[self.regArrayName + "." + self.val_field]

    def readRange(self, from_hw=True):
        resp = self.register_table.entry_get(
            self.target, flags={"from_hw": from_hw})

        all_data = []

        try:
            while True:
                x, _ = next(resp)
                all_data.append(
                    sum(x.to_dict()[self.regArrayName + "." + self.val_field]))
        except StopIteration:
            pass

        return all_data

    def writeIndex(self, index, val):
        self.register_table.entry_add(
            self.target,
            [self.register_table.make_key(
                [gc.KeyTuple('$REGISTER_INDEX', index)])],
            [self.register_table.make_data(
                [gc.DataTuple(self.regArrayName + "." + self.val_field, val)
                 ])])


class RunCAIDATrace(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        BfRuntimeTest.setUp(self, client_id, p4_program_name)

    """
    A simple function that simulates a host server. Sends an ICMP packet when it
    receives a packet with a flow id that it does not expect.
    """
    def runHost(self, at):
        global trace_complete

        while True:
            if trace_complete:
                break
            print("Host polling for packet")
            (rcv_dev, rcv_port, rcv_pkt, pkt_time) = testutils.dp_poll(
                self, 0, swports[0], timeout=1)
            if rcv_pkt is None:
                continue
            

            scapyPkt = Ether(rcv_pkt)
            sIP = scapyPkt[IP].src
            dIP = scapyPkt[IP].dst
            proto = scapyPkt[IP].proto
            dport = scapyPkt[TCP].dport
            sport = scapyPkt[TCP].sport

            print("Host received packet: ", sIP, dIP, sport, dport, 6)

            fiveTuple = socket.inet_aton(sIP) + socket.inet_aton(dIP) + \
                        sport.to_bytes(2, byteorder="little") + \
                        dport.to_bytes(2, byteorder="little") + \
                        proto.to_bytes(1, byteorder="little")
            

            if fiveTuple not in at:
                print("Host received unexpected packet, respond with ICMP packet")
                
                ipkt = testutils.simple_icmp_packet(icmp_type=3)
                scapyPkt = Ether(ipkt)

                # Add packedFiveTuple to packet as payload
                packedFiveTuple = packFiveTuple((sIP, dIP, sport, dport, proto))
                spktWithPayload = scapyPkt/packedFiveTuple

                testutils.send_packet(self, swports[0], spktWithPayload)
            else:
                print("Host recieved expected packet")

    """
    A function that polls on the CPU port and processes packets accordingly. "New flow" packets are inserted into the ACF.
    ICMP packets indicate false-positives and trigger cuckooing. 
    """
    def runCPU(self, acf):
        global trace_complete
        global gfp_count
        fp_count = 0

        # Create wrappers for register arrays
        stage_one_reg_array = RegisterArray(
            self.interface, "src", "SwitchIngress.stage_one")
        stage_two_reg_array = RegisterArray(
            self.interface, "src", "SwitchIngress.stage_two")
        stage_three_reg_array = RegisterArray(
            self.interface, "src", "SwitchIngress.stage_three")
        reg_arrays = [stage_one_reg_array,
                      stage_two_reg_array, stage_three_reg_array]

        while True:
            if trace_complete:
                break
            (rcv_dev, rcv_port, rcv_pkt, pkt_time) = testutils.dp_poll(
                self, 0, swports[-1], timeout=1)

            if rcv_pkt is None:
                continue

            print("CPU received packet")

            scapyPkt = Ether(rcv_pkt)
            proto = scapyPkt[IP].proto

            if proto == 1:
                packedFiveTuple = scapyPkt[Padding].load
                print("ICMP packet, cuckooing entry with five-tuple: ", packedFiveTuple)
                acf.adapt_false_positive(packedFiveTuple)
                fp_count += 1
            else:
                sIP = scapyPkt[IP].src
                dIP = scapyPkt[IP].dst
                dport = scapyPkt[TCP].dport
                sport = scapyPkt[TCP].sport

                packedFiveTuple = packFiveTuple((sIP, dIP, sport, dport, 6))
                print("New flow packet, inserting with five-tuple: ", packedFiveTuple)

                # If new packet, insert into ACF
                acf.insert(packedFiveTuple)

            # Very ineffecient, should only update the registers that have changed
            regState = [stage_one_reg_array.readRange(from_hw=False), stage_two_reg_array.readRange(
                from_hw=False), stage_three_reg_array.readRange(from_hw=False)]
            delta = acf.getDelta(regState)
            for item in delta:
                reg_arrays[item[0]].writeIndex(item[1], item[2])

        gfp_count = fp_count

    """
    runTest outline: 
    1. Load the trace
    2. Split into A and S
    3. Spawn CPU thread
    4. Insert A into ACF
    5. Spawn host thread
    6. Send trace packets to host
    """
    def runTest(self):
        # Load CADIA trace
        fiveTupleList = utils.load_trace(
            "/data/ACF/equinix-chicago.dirA.20140619-130900.dat", True, 0.001)

        # Insert the first 10 flowws into the ACF
        A_flows = 10 
        print(A_flows)

        # Initialize ACF with 3 stages, 2^10 buckets per stage and 1 cell per bucket
        acf = ACF.ACF(d=3, b=2**10,
                      c=1)
        at = set()

        global gfp_count
        global trace_complete
        gfp_count = 0
        trace_complete = False

        cpu_thread = threading.Thread(target=self.runCPU, args=[acf])
        cpu_thread.start()

        print("Inserting {} flows into ACF".format(A_flows))
        print(A_flows)
        insertedFlows = 0
        # Insert A flows
        for pkt in fiveTupleList:
            if len(at) < A_flows:

                # Send first packet of flow from host
                if pkt not in at:
                    (src_addr, dst_addr, sport, dport,
                     proto) = utils.parse_five_tuple(pkt)
                    ipkt = testutils.simple_tcp_packet(eth_dst='11:11:11:11:11:11',
                                                       eth_src='22:22:22:22:22:22',
                                                       ip_src=src_addr,
                                                       ip_dst=dst_addr,
                                                       ip_id=101,
                                                       ip_ttl=64,
                                                       tcp_sport=sport,
                                                       tcp_dport=dport,
                                                       with_tcp_chksum=False
                                                       )

                    #print("Sending packet to insert flow")
                    insertedFlows += 1
                    testutils.send_packet(self, swports[0], ipkt)
                    time.sleep(1)
                at.add(pkt)

            else:
                break

        host_thread = threading.Thread(target=self.runHost, args=[at])
        host_thread.start()
        print("Total inserted flows: " + str(insertedFlows))


        print("Begin sending trace packets to host")
        for pkt in fiveTupleList:
            # send packet to host
            (src_addr, dst_addr, sport, dport, proto) = utils.parse_five_tuple(pkt)
            print("Client sending: ", src_addr, dst_addr, sport, dport, 6)

            ipkt = testutils.simple_tcp_packet(eth_dst='11:11:11:11:11:11',
                                               eth_src='22:22:22:22:22:22',
                                               ip_src=src_addr,
                                               ip_dst=dst_addr,
                                               ip_id=101,
                                               ip_ttl=64,
                                               tcp_sport=sport,
                                               tcp_dport=dport,
                                               with_tcp_chksum=False
                                               )
            testutils.send_packet(self, swports[1], ipkt)
            time.sleep(1)

        trace_complete = True
        host_thread.join()
        cpu_thread.join()

        return