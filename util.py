import pickle
import random
import socket

def add_bool_arg(parser, name, default=False):
    """
    Add an bool argument to the program
    """
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--' + name, dest=name, action='store_true')
    group.add_argument('--no-' + name, dest=name, action='store_false')
    parser.set_defaults(**{name: default})


def parse_five_tuple(five_tuple_byte_string):
    src = five_tuple_byte_string[0:4]
    dst = five_tuple_byte_string[4:8]
    sport = five_tuple_byte_string[8:10]
    dport = five_tuple_byte_string[10:12]
    proto = five_tuple_byte_string[12:13]

    return (socket.inet_ntoa(src), socket.inet_ntoa(dst), int.from_bytes(sport, "little"), int.from_bytes(dport, "little"), int.from_bytes(proto, "little"))

def load_trace(fname, sample, sample_rate):
    """
    Load dumped trace generated from preprocess.py
    """
    with open(fname, "rb") as f:
        fiveTuple_list = pickle.load(f)

        # Return all packets for a random sample of flows
        if sample:

            fiveTuple_list_sample = []

            n_flows, n_pkts = get_trace_stats(fiveTuple_list)
            sample_sz = int(sample_rate * n_flows)
            flow_st = set()

            for packet in fiveTuple_list:
                flow_st.add(packet)

            sample_flows = set(random.sample(list(flow_st), sample_sz))

            for packet in fiveTuple_list:
                if packet in sample_flows:
                    fiveTuple_list_sample.append(packet)

            print(n_flows, sample_sz, n_pkts, len(fiveTuple_list_sample))

            return fiveTuple_list_sample
        else:
            return fiveTuple_list

    raise Exception("Trace not exists")


def get_trace_stats(fiveTuple_list):
    """
    Get #flows, #pkts from the trace
    """
    st = set()
    for fiveTuple in fiveTuple_list:
        st.add(fiveTuple)
    n_flows = len(st)
    n_pkts = len(fiveTuple_list)
    return n_flows, n_pkts
