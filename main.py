# Autor: Petra Miková
# Aktuálna verzia programu obsahuje iba riešenie úlohy 1
import pprint

from scapy.all import rdpcap
import ruamel.yaml
from ruamel.yaml.scalarstring import LiteralScalarString

class Packet:
    def __init__(self, frame_number, len_frame_pcap, len_frame_medium, frame_type,
                 src_mac, dst_mac, hexa_frame,
                 pid=None, sap=None, ether_type=None, src_ip=None, dst_ip=None, protocol=None, src_port=None,
                 dst_port=None, app_protocol=None, icmp_type=None, icmp_id=None, icmp_seq=None):
        self.frame_number = frame_number
        self.len_frame_pcap = len_frame_pcap
        self.len_frame_medium = len_frame_medium
        self.frame_type = frame_type
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.ether_type = ether_type
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.app_protocol = app_protocol
        self.pid = pid
        self.sap = sap
        self.icmp_type = icmp_type
        self.icmp_id = icmp_id
        self.icmp_seq = icmp_seq
        self.hexa_frame = hexa_frame

    def to_dict_tcp(self):
        packet_dict = {
            'frame_number': self.frame_number,
            'len_frame_pcap': self.len_frame_pcap,
            'len_frame_medium': self.len_frame_medium,
            'frame_type': self.frame_type,
            'src_mac': self.src_mac,
            'dst_mac': self.dst_mac,
            'ether_type': self.ether_type,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'protocol': self.protocol,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'app_protocol': self.app_protocol,
            'hexa_frame': self.hexa_frame
        }
        return packet_dict

    def to_dict_icmp(self):
        packet_dict = {
            'frame_number': self.frame_number,
            'len_frame_pcap': self.len_frame_pcap,
            'len_frame_medium': self.len_frame_medium,
            'frame_type': self.frame_type,
            'src_mac': self.src_mac,
            'dst_mac': self.dst_mac,
            'ether_type': self.ether_type,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'protocol': self.protocol,
            'icmp_type': self.icmp_type,
            'icmp_id': self.icmp_id,
            'icmp_seq': self.icmp_seq,
            'hexa_frame': self.hexa_frame
        }
        return packet_dict


class IPv4_sender:
    def __init__(self, node, number_of_send_packets):
        self.node = node
        self.number_of_send_packets = number_of_send_packets


class Communication:
    def __init__(self, number_comm, source_ip, dest_ip, source_port, dest_port, is_complete, packet_list):
        self.number_comm = number_comm
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.is_complete = is_complete
        self.packet_list = packet_list

    def add_packet(self, packet):
        self.packet_list.append(packet)

    def complete_comm_dict_tcp(self):
        return {
            'number_comm': self.number_comm,
            'src_comm': self.source_ip,
            'dst_comm': self.dest_ip,
            'packets': [packet.to_dict_tcp() for packet in self.packet_list]
        }

    def incomplete_comm_dict_tcp(self):
        return{
            'number_comm': self.number_comm,
            'packets': [packet.to_dict_tcp() for packet in self.packet_list]
        }

    def complete_comm_dict_icmp(self):
        return {
            'number_comm': self.number_comm,
            'src_comm': self.source_ip,
            'dst_comm': self.dest_ip,
            'packets': [packet.to_dict_icmp() for packet in self.packet_list]
        }

    def incomplete_comm_dict_icmp(self):
        return{
            'number_comm': self.number_comm,
            'packets': [packet.to_dict_icmp() for packet in self.packet_list]
        }

# Funkcia pre definovanie dĺžky rámca
def frame_length_medium(packet):
    if len(packet) < 60:
        length = 64  # Minimálna dĺžka rámca s paddingom a FCS
    else:
        length = len(packet) + 4  # Pridanie FCS k dĺžke

    return length


# Funkcia pre výpis hex dumpu v požadovanom tvare
def print_hex_dump(packet):
    hex_string = bytes(packet).hex()

    hex_dump_formatted = ''

    for i in range(0, len(hex_string), 2):
        hex_dump_formatted += hex_string[i:i + 2].upper() + ' '

        if (i + 2) % 32 == 0:
            hex_dump_formatted = hex_dump_formatted.rstrip()
            hex_dump_formatted += '\n'

    hex_dump_formatted = hex_dump_formatted.rstrip()

    return hex_dump_formatted + '\n'


# Funkcia pre správny formát výpisu MAC adries
def mac_address_format(mac_address):
    string_mac = str(mac_address)
    string_mac_capitals = string_mac.upper()

    mac_formatted = ''

    for i in range(0, len(string_mac_capitals), 2):
        mac_formatted += string_mac_capitals[i:i + 2] + ':'

    return mac_formatted[:-1]


# Funkcia pre získanie typu rámca z bytov v packete
def frame_type(data_in_bytes):
    frame_part3_hex = data_in_bytes[12:14].hex()
    part_check_raw = data_in_bytes[14:16].hex()
    part_check_snap = data_in_bytes[14:15].hex()

    decimal_part3_length = int(frame_part3_hex, 16)

    if decimal_part3_length > 1500:
        frame_type_string = "ETHERNET II"
    else:
        if part_check_raw == "ffff":
            frame_type_string = "IEEE 802.3 RAW"
        elif part_check_snap == "aa":
            frame_type_string = "IEEE 802.3 LLC & SNAP"
        else:
            frame_type_string = "IEEE 802.3 LLC"
    return frame_type_string


def hex_pairs_to_ip(hex_pairs):
    ip_parts = [hex_pairs[i:i + 2] for i in range(0, len(hex_pairs), 2)]  # Split into pairs
    try:
        decimal_parts = [str(int(hex_pair, 16)) for hex_pair in ip_parts]  # Convert to decimal
        ip_address = ".".join(decimal_parts)  # Join parts with dots
        return ip_address
    except ValueError:
        return "Invalid input"


# Funkcia pre získanie údajov pre ďalšiu analýzu z externých súborov
def get_data_from_file(file_string):
    data = {}
    with open(file_string, "r") as file:
        for line in file:
            parts = line.strip().split(' ', 1)
            if len(parts) == 2:
                hexa = parts[0]
                name = parts[1]
                data[hexa] = name

    return data


def find_max_senders(ip_packet_counts):
    max_count = max(ip_packet_counts, key=lambda x: x['number_of_send_packets'])['number_of_send_packets']
    max_senders = [ip['node'] for ip in ip_packet_counts if ip['number_of_send_packets'] == max_count]
    return max_senders


def filter_tcp_comms(tcp_packets, protocol):
    HTTP_comms = []
    FTP_DATA_comms = []
    FTP_CONTROL_comms = []
    SSH_comms = []
    TELNET_comms = []
    HTTPS_comms = []

    for frame in tcp_packets:
        get_protocol = frame.app_protocol

        if protocol == "HTTP":
            if get_protocol == "http":
                HTTP_comms.append(frame)
        elif protocol == "FTP-DATA":
            if get_protocol == "ftp-data":
                FTP_DATA_comms.append(frame)
        elif protocol == "FTP-CONTROL":
            if get_protocol == "ftp-control":
                FTP_CONTROL_comms.append(frame)
        elif protocol == "SSH":
            if get_protocol == "ssh":
                SSH_comms.append(frame)
        elif protocol == "TELNET":
            if get_protocol == "telnet":
                TELNET_comms.append(frame)
        elif protocol == "HTTPS":
            if get_protocol == "https":
                HTTPS_comms.append(frame)

    if protocol == "HTTP":
        return HTTP_comms
    elif protocol == "FTP-DATA":
        return FTP_DATA_comms
    elif protocol == "FTP-CONTROL":
        return FTP_CONTROL_comms
    elif protocol == "SSH":
        return SSH_comms
    elif protocol == "TELNET":
        return TELNET_comms
    elif protocol == "HTTPS":
        return HTTPS_comms


def group_comms(comms_list):
    communications = []
    for frame in comms_list:
        if len(communications) == 0:
            comm = Communication(0, frame.src_ip, frame.dst_ip, frame.src_port, frame.dst_port, 0, packet_list=[])
            communications.append(comm)
            comm.add_packet(frame)
        else:
            no_of_comm = 0
            is_new_comm = 1
            for comm in communications:
                if ((
                        frame.src_ip == comm.source_ip and frame.dst_ip == comm.dest_ip and frame.src_port == comm.source_port and
                        frame.dst_port == comm.dest_port) or (
                        frame.src_ip == comm.dest_ip and frame.dst_ip == comm.source_ip and frame.src_port == comm.dest_port and frame.dst_port == comm.source_port)):
                    communications[no_of_comm].add_packet(frame)
                    is_new_comm = 0
                    break
                no_of_comm += 1
            if is_new_comm == 1:
                comm = Communication(0, frame.src_ip, frame.dst_ip, frame.src_port, frame.dst_port, 0,packet_list=[])
                communications.append(comm)
                comm.add_packet(frame)

    for comm in communications:
        comm.source_ip = comm.packet_list[0].src_ip
        comm.dest_ip = comm.packet_list[0].dst_ip

    return communications

def check_isl_comm(hexdump):
    isl_check_string = ''.join(hexdump[:5])
    if isl_check_string == "01000C0000" or isl_check_string == "0C000C0000":
        return hexdump[26:]

def analyze_completeness_of_comm(filtered_comms):
    flag_complete = 0
    complete_count = 0
    incomplete_count = 0
    for comm in filtered_comms:
        if len(comm.packet_list) >= 3:
            complete = 0
            hexdump1 = check_isl_comm(comm.packet_list[0].hexa_frame.split())
            hexdump2 = check_isl_comm(comm.packet_list[1].hexa_frame.split())
            hexdump3 = check_isl_comm(comm.packet_list[2].hexa_frame.split())

            flag1 = hexdump1[47]
            flag2 = hexdump2[47]
            flag3 = hexdump3[47]

            if flag1 == '02' and flag2 == '12' and (flag3 == '18' or flag3 == '10'):  # 3-way handshake - SYN, SYN-ACK, ACK
                complete = 0.5

            if complete == 0:
                if len(comm.packet_list) >= 4:
                    hexdump4 = check_isl_comm(comm.packet_list[4].hexa_frame.split())
                    flag4 = hexdump4[47]
                    if flag1 == '02' and flag2 == '02' and (flag3 == '18' or flag3 == '10') and (flag4 == '18' or flag4 == '10'):  # 3-way handshake - SYN, SYN, ACK, ACK
                        complete = 0.5

            if len(comm.packet_list) >= 5: # RST koniec
                hexdump_last = check_isl_comm(comm.packet_list[len(comm.packet_list) - 1].hexa_frame.split())
                flag_last = hexdump_last[47]

                if flag_last == '14' or flag_last == '04':
                    complete = 1
                    complete_count += 1
                    flag_complete = 1
                    comm.number_comm = complete_count

            if complete == 0.5 and len(comm.packet_list) >= 7:
                hexdump_last4 = check_isl_comm(comm.packet_list[len(comm.packet_list) - 4].hexa_frame.split())
                hexdump_last3 = check_isl_comm(comm.packet_list[len(comm.packet_list) - 3].hexa_frame.split())
                hexdump_last2 = check_isl_comm(comm.packet_list[len(comm.packet_list) - 2].hexa_frame.split())
                hexdump_last1 = check_isl_comm(comm.packet_list[len(comm.packet_list) - 1].hexa_frame.split())

                flag_last4 = hexdump_last4[47]
                flag_last3 = hexdump_last3[47]
                flag_last2 = hexdump_last2[47]
                flag_last1 = hexdump_last1[47]

                if (flag_last4 == "11" or flag_last4 == "01" or flag_last4 == "19") and flag_last3 == "10" and (flag_last2 == "11" or flag_last2 == "01" or flag_last2 == "19") and flag_last1 == "10":
                    complete = 1
                    complete_count += 1
                    flag_complete = 1
                    comm.number_comm = complete_count

                if complete == 0.5:
                    if (flag_last4 == "11" or flag_last4 == "01" or flag_last4 == "19") and (flag_last3 == "11" or flag_last3 == "01" or flag_last3 == "19") and flag_last2 == "10" and flag_last1 == "10":
                        complete = 1
                        complete_count += 1
                        flag_complete = 1
                        comm.number_comm = complete_count

        if flag_complete == 0:
            incomplete_count += 1
            comm.number_comm = incomplete_count

        comm.is_complete = complete
        flag_complete = 0
    return filtered_comms

def distinguish_tcp_comms(filtered_comms):
    complete_comms = []
    incomplete_comms = []

    for comm in filtered_comms:
        if (comm.is_complete == 0 or comm.is_complete == 0.5) and comm.number_comm == 1: # vypis prvej nekompletnej
            incomplete_comms.append(comm.incomplete_comm_dict_tcp())
        elif comm.is_complete == 1: #kompletne komunikacie
            complete_comms.append(comm.complete_comm_dict_tcp())

    yaml_filename = 'packets_http.yaml'

    yaml_data = {
        'name': 'PKS2023/24',
        'pcap_name': pcap_filename,
        'filter_name': "HTTP",
        'complete_comms': complete_comms,
        'incomplete_comms': incomplete_comms,
    }

    with open(yaml_filename, 'w') as yaml_file:
        yaml = ruamel.yaml.YAML()
        yaml.dump(yaml_data, yaml_file)


def tftp_comms(udp_packets):
    comms = []
    counter = 0
    data_lengths = []
    prev_frame = None
    communication_state = 0 # 1 - start, 2 - getting data pckgs, 3 - found shorter data pckg, 4- successful end with ack
    for udp_frame in udp_packets:
        if udp_frame.dst_port == 69:
            communication_state = 1
            communication = Communication(counter + 1, udp_frame.src_ip, udp_frame.dst_ip, udp_frame.src_port, udp_frame.dst_port, 0, packet_list=[])
            communication.add_packet(udp_frame)
            comms.append(communication)
        elif communication_state == 1:
            hexdump = udp_frame.hexa_frame.split()
            opcode = ''.join(hexdump[42:44])
            if opcode == "0003": #ide o datapacket za zaciatkom komunikacir
                comms[counter].add_packet(udp_frame)
                communication_state = 2
            else:
                communication_state = 0
        elif communication_state == 2:
            if udp_frame.src_port == prev_frame.dst_port and udp_frame.dst_port == prev_frame.src_port:
                comms[counter].add_packet(udp_frame)
                hexdump = udp_frame.hexa_frame.split()
                opcode = ''.join(hexdump[42:44])
                if opcode == "0003":
                    if len(data_lengths) == 0:
                        data_lengths.append(len(hexdump[46:]))
                    elif len(data_lengths) > 1 and len(hexdump[46:]) not in data_lengths:
                        communication_state = 3
                    else:
                        data_lengths.append(len(hexdump[46:]))
                elif opcode == "0005":
                    communication_state = 0
                    comms[counter].is_complete = 1
                    counter += 1
                    data_lengths = []
                elif opcode != "0004":
                    communication_state = 0
                    comms[counter].is_complete = 0
                    counter += 1
            else:
                comms[counter].add_packet(udp_frame)
                hexdump = udp_frame.hexa_frame.split()
                opcode = ''.join(hexdump[42:44])
                if opcode == "0005":
                    communication_state = 0
                    comms[counter].is_complete = 1
                    counter += 1
                    data_lengths = []

        elif communication_state == 3:
            comms[counter].add_packet(udp_frame)
            hexdump = udp_frame.hexa_frame.split()
            opcode = ''.join(hexdump[42:44])
            if opcode == "0004":
                communication_state = 4
                comms[counter].is_complete = 1
                counter += 1
                data_lengths = []
            else:
                communication_state = 0
                comms[counter].is_complete = 0
                counter += 1

        prev_frame = udp_frame

    for comm in comms:
        comm.source_ip = comm.packet_list[0].src_ip
        comm.dest_ip = comm.packet_list[0].dst_ip

    return comms

def distinguish_tftp_comms(filtered_comms):
    complete_comms = []

    for comm in filtered_comms:
        if comm.is_complete == 1: #kompletne komunikacie
            complete_comms.append(comm.complete_comm_dict_tcp())

    yaml_filename = 'packets_tftp.yaml'

    yaml_data = {
        'name': 'PKS2023/24',
        'pcap_name': pcap_filename,
        'filter_name': "TFTP",
        'complete_comms': complete_comms,
    }

    with open(yaml_filename, 'w') as yaml_file:
        yaml = ruamel.yaml.YAML()
        yaml.dump(yaml_data, yaml_file)

def icmp_comms(icmp_packets):
    grouped_icmp_comms = group_comms(icmp_packets)
    complete_comms = []
    incomplete_comms = []
    complete_counter = 1
    incomplete_counter = 1
    incomplete_packets = []

    for comm in grouped_icmp_comms:
        complete_comms.append(comm)
        echo_requests = {}
        for packet in comm.packet_list:
            if packet.icmp_type == "ECHO REQUEST":
                key = (packet.icmp_id, packet.icmp_seq)
                echo_requests[key] = packet
            elif packet.icmp_type == "ECHO REPLY" or packet.icmp_type == "Time Exceeded":
                key = (packet.icmp_id, packet.icmp_seq)
                if key in echo_requests:
                    del echo_requests[key]
                else:
                    incomplete_packets.append(packet)
            else:
                incomplete_packets.append(packet)

    for comm in complete_comms:
        if len(comm.packet_list) >= 2:
            comm.number_comm = complete_counter
            complete_counter += 1
            updated_packet_list = [packet for packet in comm.packet_list if packet not in incomplete_packets]
            comm.packet_list = updated_packet_list
            complete_comms.remove(comm)
            complete_comms.append(comm.complete_comm_dict_icmp())


    for packet in incomplete_packets:
        comm = Communication(incomplete_counter, packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, 0, packet_list=[])
        incomplete_counter += 1
        comm.packet_list.append(packet)
        comm = comm.incomplete_comm_dict_icmp()
        incomplete_comms.append(comm)

    yaml_filename = 'packets_icmp.yaml'

    yaml_data = {
        'name': 'PKS2023/24',
        'pcap_name': pcap_filename,
        'filter_name': "ICMP",
        'complete_comms': complete_comms,
        'partial_comms': incomplete_comms
    }

    with open(yaml_filename, 'w') as yaml_file:
        yaml = ruamel.yaml.YAML()
        yaml.dump(yaml_data, yaml_file)

yaml_filename = 'packets_output.yaml'
pcap_filename = input("Zadajte názov súboru na analýzu v tvare názovsúboru.pcap:")
packets = rdpcap(pcap_filename)
frame_number = 1
packet_frames = []
ip_add_senders = {}
ip_address_counter = []
tcp_packets = []
udp_packets = []
icmp_packets = []

for packet in packets:
    data_in_bytes = bytes(packet)
    ISL_header_check_hex = data_in_bytes[0:5].hex()
    if ISL_header_check_hex == "01000c0000" or ISL_header_check_hex == "0c000c0000":
        # Sledujeme či má rámec ISL header, ak áno posúvame sa o jeho celú dĺžku
        data_in_bytes = data_in_bytes[26:]

    frame_type_result = frame_type(data_in_bytes)

    frame = Packet(frame_number=frame_number, len_frame_pcap=len(packet), len_frame_medium=frame_length_medium(packet),
                   frame_type=frame_type_result, src_mac=mac_address_format(data_in_bytes[6:12].hex()),
                   dst_mac=mac_address_format(data_in_bytes[0:6].hex()),
                   hexa_frame=LiteralScalarString(print_hex_dump(packet)))

    if frame_type_result == "ETHERNET II":
        ethertypes = get_data_from_file("Protocols/ETHERTYPE.txt")
        frame_part3_hex = data_in_bytes[12:14].hex().upper()
        frame_part3_string = "0x" + frame_part3_hex
        ethertype_name = ethertypes.get(frame_part3_string, "Unknown type")
        frame.ether_type = ethertype_name
        if ethertype_name not in ["LLDP", "IPv6", "Unknown type"]:
            source_ip = data_in_bytes[26:30].hex()
            frame.src_ip = hex_pairs_to_ip(source_ip)
            dest_ip = data_in_bytes[30:34].hex()
            frame.dst_ip = hex_pairs_to_ip(dest_ip)
        if ethertype_name == "IPv4":
            protocols = get_data_from_file("Protocols/IP_PROTOCOLS.txt")
            protocol = data_in_bytes[23:24].hex()
            protocol_decimal = str(int(protocol, 16))
            protocol_name = protocols.get(protocol_decimal, "Unknown type")
            frame.protocol = protocol_name

            if hex_pairs_to_ip(source_ip) not in ip_add_senders:
                ip = hex_pairs_to_ip(source_ip)
                count = 1
                ip_add_senders[ip] = count
            else:
                ip_add_senders[hex_pairs_to_ip(source_ip)] += 1

            if hex_pairs_to_ip(dest_ip) not in ip_add_senders:
                ip = hex_pairs_to_ip(dest_ip)
                count = 1
                ip_add_senders[ip] = count
            else:
                ip_add_senders[hex_pairs_to_ip(dest_ip)] += 1

            if protocol_name == "TCP" or protocol_name == "UDP":
                source_port = data_in_bytes[34:36].hex()
                source_port_decimal = int(source_port, 16)
                frame.src_port = source_port_decimal
                dest_port = data_in_bytes[36:38].hex()
                dest_port_decimal = int(dest_port, 16)
                frame.dst_port = dest_port_decimal
                if protocol_name == "TCP":
                    tcp_server_ports = get_data_from_file("Protocols/TCP.txt")
                    if str(source_port_decimal) in tcp_server_ports:
                        frame.app_protocol = tcp_server_ports.get(str(source_port_decimal))
                    elif frame.app_protocol is None and str(dest_port_decimal) in tcp_server_ports:
                        frame.app_protocol = tcp_server_ports.get(str(dest_port_decimal))
                    tcp_packets.append(frame)

                elif protocol_name == "UDP":
                    udp_server_ports = get_data_from_file("Protocols/UDP.txt")
                    if str(source_port_decimal) in udp_server_ports:
                        frame.app_protocol = udp_server_ports.get(str(source_port_decimal))
                    elif frame.app_protocol is None and str(dest_port_decimal) in udp_server_ports:
                        frame.app_protocol = udp_server_ports.get(str(dest_port_decimal))
                    udp_packets.append(frame)
            if protocol_name == "ICMP":
                icmp_codes = get_data_from_file("Protocols/ICMP.txt")
                ihl_byte = str(data_in_bytes[14:15].hex())
                ihl = ihl_byte[1]
                decimal_ihl = int(ihl, 16) * 4
                icmp_type = int(data_in_bytes[(14 + decimal_ihl):(14 + decimal_ihl + 1)].hex(), 16)
                frame.icmp_type = icmp_codes.get(str(icmp_type))
                identifier = int(data_in_bytes[(14 + decimal_ihl + 4): (14 + decimal_ihl + 6)].hex(),16)
                frame.icmp_id = identifier
                sequence = int(data_in_bytes[(14 + decimal_ihl + 6): (14 + decimal_ihl + 8)].hex(),16)
                frame.icmp_seq = sequence
                icmp_packets.append(frame)

    if frame_type_result == "IEEE 802.3 LLC & SNAP":
        pids = get_data_from_file("Protocols/PID.txt")
        frame_pid_hex = data_in_bytes[20:22].hex().upper()
        frame_pid_string = "0x" + frame_pid_hex
        pid_name = pids.get(frame_pid_string, "Unknown type")
        frame.pid = pid_name

    if frame_type_result == "IEEE 802.3 LLC":
        saps = get_data_from_file("Protocols/LLC.txt")
        frame_sap_hex = data_in_bytes[14:15].hex().upper()
        frame_sap_string = "0x" + frame_sap_hex
        sap_name = saps.get(frame_sap_string, "Unknown type")
        frame.sap = sap_name

    # Vyfiltrujeme preč atribúty s None value pre správny výpis do yamlu
    frame_dict = {k: v for k, v in frame.__dict__.items() if v is not None}

    packet_frames.append(frame_dict)
    frame_number += 1

for node, packets_sent in ip_add_senders.items():
    ipv4_sender = IPv4_sender(node, packets_sent)
    ipv4_dict = {k: v for k, v in ipv4_sender.__dict__.items() if v is not None}
    ip_address_counter.append(ipv4_dict)

max_senders = find_max_senders(ip_address_counter)

icmp_comms(icmp_packets)

yaml_data = {
    'name': 'PKS2023/24',
    'pcap_name': pcap_filename,
    'packets': packet_frames,
    'ipv4_senders': ip_address_counter,
    'max_send_packets_by': max_senders,
}

with open(yaml_filename, 'w') as yaml_file:
    yaml = ruamel.yaml.YAML()
    yaml.dump(yaml_data, yaml_file)