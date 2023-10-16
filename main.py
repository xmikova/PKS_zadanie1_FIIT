# Zadanie 1: analyzátor sieťovej komunikácie
# PKS - ZS 2023/2024
# Autor: Petra Miková

from scapy.all import rdpcap
import ruamel.yaml
from ruamel.yaml.scalarstring import LiteralScalarString

# Trieda Packet, ktorá obsahuje základ outputu pre yaml a podslovníky pre výpisy špecifických rámcov
class Packet:
    def __init__(self, frame_number, len_frame_pcap, len_frame_medium, frame_type,
                 src_mac, dst_mac, hexa_frame,
                 pid=None, sap=None, ether_type=None, src_ip=None, dst_ip=None, protocol=None, src_port=None,
                 dst_port=None, app_protocol=None, icmp_type=None, icmp_id=None, icmp_seq=None, arp_opcode=None, id=None, flags_mf= None, frag_offset=None):
        self.frame_number = frame_number
        self.len_frame_pcap = len_frame_pcap
        self.len_frame_medium = len_frame_medium
        self.frame_type = frame_type
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.ether_type = ether_type
        self.arp_opcode = arp_opcode
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.id= id
        self.flags_mf = flags_mf
        self.frag_offset= frag_offset
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

    # Slovník pre výpis TCP komunikácii
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

    # Slovník pre výpis kompletných ICMP komunikácii
    def to_dict_icmp_complete(self):
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

    # Slovník pre výpis nekompletných ICMP komunikácii
    def to_dict_icmp_incomplete(self):
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
            'hexa_frame': self.hexa_frame
        }
        return packet_dict

    # Slovník pre výpis ARP komunikácii
    def to_dict_arp(self):
        packet_dict = {
            'frame_number': self.frame_number,
            'len_frame_pcap': self.len_frame_pcap,
            'len_frame_medium': self.len_frame_medium,
            'frame_type': self.frame_type,
            'src_mac':self.src_mac,
            'dst_mac': self.dst_mac,
            'ether_type': self.ether_type,
            'arp_opcode': self.arp_opcode,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'hexa_frame': self.hexa_frame
        }
        return packet_dict

# Trieda IPv4_sender pre výstup IP adries všetkých odosielajúcich uzlov a koľko paketov odoslali
class IPv4_sender:
    def __init__(self, node, number_of_send_packets):
        self.node = node
        self.number_of_sent_packets = number_of_send_packets

# Trieda Communication pre štruktúru každej hlavičky komunikácie a podslovníky pre výpis špecifických komunikácii
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

    # Slovník pre výpis kompletných TCP komunikácii
    def complete_comm_dict_tcp(self):
        return {
            'number_comm': self.number_comm,
            'src_comm': self.source_ip,
            'dst_comm': self.dest_ip,
            'packets': [packet.to_dict_tcp() for packet in self.packet_list]
        }

    # Slovník pre výpis nekompletných TCP komunikácii
    def incomplete_comm_dict_tcp(self):
        return{
            'number_comm': self.number_comm,
            'packets': [packet.to_dict_tcp() for packet in self.packet_list]
        }

    # Slovník pre výpis kompletných ICMP komunikácii
    def complete_comm_dict_icmp(self):
        return {
            'number_comm': self.number_comm,
            'src_comm': self.source_ip,
            'dst_comm': self.dest_ip,
            'packets': [packet.to_dict_icmp_complete() for packet in self.packet_list]
        }

    # Slovník pre výpis nekompletných ICMP komunikácii
    def incomplete_comm_dict_icmp(self):
        return{
            'number_comm': self.number_comm,
            'packets': [packet.to_dict_icmp_incomplete() for packet in self.packet_list]
        }

    # Slovník pre výpis ARP komunikácii
    def arp_comm(self):
        return{
            'number_comm': self.number_comm,
            'packets': [packet.to_dict_arp() for packet in self.packet_list]
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


# Funkcia pre správny výpis IP adresy
def hex_pairs_to_ip(hex_pairs):
    ip_parts = [hex_pairs[i:i + 2] for i in range(0, len(hex_pairs), 2)]
    decimal_parts = [str(int(hex_pair, 16)) for hex_pair in ip_parts]
    ip_address = ".".join(decimal_parts)
    return ip_address


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


# Funkcia pre nájdenie IP adresy/adries odosielajúcej najviac packetov
def find_max_senders(ip_packet_counts):
    max_count = max(ip_packet_counts, key=lambda x: x['number_of_sent_packets'])['number_of_sent_packets']
    max_senders = [ip['node'] for ip in ip_packet_counts if ip['number_of_sent_packets'] == max_count]
    return max_senders


# Funkcia ktorá berie list TCP packetov ako vstup a vyfiltruje len packety podľa zadaného protokolu
def filter_tcp_comms(tcp_packets, protocol):
    HTTP_comms = []
    FTP_DATA_comms = []
    FTP_CONTROL_comms = []
    SSH_comms = []
    TELNET_comms = []
    HTTPS_comms = []

    for frame in tcp_packets:
        if frame.app_protocol == "HTTP":
            HTTP_comms.append(frame)
        elif frame.app_protocol == "FTP-DATA":
            FTP_DATA_comms.append(frame)
        elif frame.app_protocol == "FTP-CONTROL":
            FTP_CONTROL_comms.append(frame)
        elif frame.app_protocol == "SSH":
            SSH_comms.append(frame)
        elif frame.app_protocol == "TELNET":
            TELNET_comms.append(frame)
        elif frame.app_protocol == "HTTPS":
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


# Funkcia ktorá zgrupí packety do komunikácií na základe IP adries a portov
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


# Funkcia pre zistenie, či rámec obsahuje ISL header
def check_isl_comm(hexdump):
    isl_check_string = ''.join(hexdump[:5])
    if isl_check_string == "01000C0000" or isl_check_string == "0C000C0000":
        return hexdump[26:]
    else:
        return hexdump


# Funkcia, ktorá analyzuje kompletnosť komunikácii v zadanom liste
def analyze_completeness_of_comm(filtered_comms):
    flag_complete = 0
    complete_count = 0
    incomplete_count = 0
    complete = 0
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
                    hexdump4 = check_isl_comm(comm.packet_list[3].hexa_frame.split())
                    flag4 = hexdump4[47]
                    if flag1 == '02' and flag2 == '02' and (flag3 == '18' or flag3 == '10') and (flag4 == '18' or flag4 == '10'):  # 3-way handshake - SYN, SYN, ACK, ACK
                        complete = 0.5

            if len(comm.packet_list) >= 5:  # RST koniec
                hexdump_last2 = check_isl_comm(comm.packet_list[len(comm.packet_list) - 2].hexa_frame.split())
                hexdump_last = check_isl_comm(comm.packet_list[len(comm.packet_list) - 1].hexa_frame.split())
                flag_last2 = hexdump_last2[47]
                flag_last = hexdump_last[47]

                if flag_last == '14' or flag_last == '04':  # RST
                    complete = 1
                    complete_count += 1
                    flag_complete = 1
                    comm.number_comm = complete_count

                if flag_last == "10" and (flag_last2 == '14' or flag_last2 == '04'): # RST + ACK
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

                # 4-way handshake - FIN, ACK, FIN, ACK / FIN-ACK, ACK, FIN-ACK, ACK
                if (flag_last4 == "11" or flag_last4 == "01" or flag_last4 == "19") and flag_last3 == "10" and (flag_last2 == "11" or flag_last2 == "01" or flag_last2 == "19") and flag_last1 == "10":
                    complete = 1
                    complete_count += 1
                    flag_complete = 1
                    comm.number_comm = complete_count

                if complete == 0.5:
                    # FIN, FIN, ACK, ACK
                    if (flag_last4 == "11" or flag_last4 == "01" or flag_last4 == "19") and (flag_last3 == "11" or flag_last3 == "01" or flag_last3 == "19") and flag_last2 == "10" and flag_last1 == "10":
                        complete = 1
                        complete_count += 1
                        flag_complete = 1
                        comm.number_comm = complete_count

            if complete == 0.5 and len(comm.packet_list) >= 5:
                hexdump_last3 = check_isl_comm(comm.packet_list[len(comm.packet_list) - 3].hexa_frame.split())
                hexdump_last2 = check_isl_comm(comm.packet_list[len(comm.packet_list) - 2].hexa_frame.split())
                hexdump_last1 = check_isl_comm(comm.packet_list[len(comm.packet_list) - 1].hexa_frame.split())

                flag_last3 = hexdump_last3[47]
                flag_last2 = hexdump_last2[47]
                flag_last1 = hexdump_last1[47]

                # FIN, ACK, FIN / FIN-ACK, ACK, FIN-ACK
                if (flag_last1 == "11" or flag_last1 == "19") and flag_last2 == "10" and (flag_last3 == "11" or flag_last3 == "19"):
                    complete = 1
                    complete_count += 1
                    flag_complete = 1
                    comm.number_comm = complete_count

            if complete == 0.5 and len(comm.packet_list) >= 6:
                hexdump_last2 = check_isl_comm(comm.packet_list[len(comm.packet_list) - 2].hexa_frame.split())
                hexdump_last1 = check_isl_comm(comm.packet_list[len(comm.packet_list) - 1].hexa_frame.split())

                flag_last2 = hexdump_last2[47]
                flag_last1 = hexdump_last1[47]

                # FIN-ACK, FIN-ACK
                if (flag_last1 == "11" or flag_last1 == "19") and (flag_last2 == "11" or flag_last2 == "19"):
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


# Funkcia pre rozdelenie TCP komunikácii do listov podľa ich kompletnosti - na kompletné a nekompletné, a finálny výpis do yamlu
def distinguish_tcp_comms(filtered_comms):
    complete_comms = []
    incomplete_comms = []
    protocol = ""

    for comm in filtered_comms:
        if (comm.is_complete == 0 or comm.is_complete == 0.5) and comm.number_comm == 1: # Výpis len prvej nekompletnej
            incomplete_comms.append(comm.incomplete_comm_dict_tcp())
        elif comm.is_complete == 1:
            complete_comms.append(comm.complete_comm_dict_tcp())
        if protocol == "":
            for packet in comm.packet_list:
                protocol = packet.app_protocol

    yaml_filename = 'packets_' + protocol + '.yaml'

    yaml_data = {
        'name': 'PKS2023/24',
        'pcap_name': pcap_filename,
        'filter_name': "HTTP",
        'complete_comms': complete_comms,
        'partial_comms': incomplete_comms,
    }

    with open(yaml_filename, 'w') as yaml_file:
        yaml = ruamel.yaml.YAML()
        yaml.dump(yaml_data, yaml_file)


# Funkcia pre analýzu TFTP komunikácii
def tftp_comms(udp_packets):
    comms = []
    counter = 0
    data_lengths = []
    prev_frame = None
    communication_state = 0
    # Flag communication_state: 1 - začiatok komunikácie, 2 - získavanie data packets, 3 - nájdený finálny kratší data packet, 4- ukončenie komunikácie
    for udp_frame in udp_packets:
        if udp_frame.dst_port == 69:
            communication_state = 1
            communication = Communication(counter + 1, udp_frame.src_ip, udp_frame.dst_ip, udp_frame.src_port, udp_frame.dst_port, 0, packet_list=[])
            communication.add_packet(udp_frame)
            comms.append(communication)
        elif communication_state == 1:
            hexdump = udp_frame.hexa_frame.split()
            opcode = ''.join(hexdump[42:44])
            if opcode == "0003": # Prvý data packet za začiatkom komunikácie
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
                        # Nájdenie kratšieho data packetu
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
            # Ukončenie komunikácie
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


# Funkcia pre rozdelenie TFTP komunikácii do listov podľa ich kompletnosti - na kompletné a nekompletné, a finálny výpis do yamlu
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


# Funkcia, ktorá analyzuje ICMP komunikácie
def icmp_comms(icmp_packets):
    grouped_icmp_comms = group_comms(icmp_packets)
    complete_comms = []
    incomplete_comms = []
    complete_counter = 1
    incomplete_counter = 1
    incomplete_packets = []
    complete_comms_final = []

    # Hľadanie párov REQUEST - REPLY/TIME EXCEEDED
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

        # Zvyšné requesty sa pridajú medzi nekompletné packety
        for request_packet in echo_requests.values():
            incomplete_packets.append(request_packet)

    for comm in complete_comms:
        if len(comm.packet_list) >= 2:
            comm.number_comm = complete_counter
            updated_packet_list = []
            for packet in comm.packet_list:
                if all(packet.frame_number != p.frame_number for p in incomplete_packets):
                    updated_packet_list.append(packet)
            if (len(updated_packet_list) % 2 != 0) or (len(updated_packet_list) == 0):
                continue
            comm.packet_list = updated_packet_list
            complete_counter += 1
            complete_comms_final.append(comm.complete_comm_dict_icmp())

    incomplete_packets_grouped = group_comms(incomplete_packets)
    for comm in incomplete_packets_grouped:
        comm.number_comm = incomplete_counter
        incomplete_counter += 1
        comm = comm.incomplete_comm_dict_icmp()
        incomplete_comms.append(comm)

    yaml_filename = 'packets_icmp.yaml'

    yaml_data = {
        'name': 'PKS2023/24',
        'pcap_name': pcap_filename,
        'filter_name': "ICMP",
        'complete_comms': complete_comms_final,
        'partial_comms': incomplete_comms
    }

    with open(yaml_filename, 'w') as yaml_file:
        yaml = ruamel.yaml.YAML()
        yaml.dump(yaml_data, yaml_file)


# Funkcia, ktorá analyzuje ARP komunikácie
def arp_comms(arp_packets):
    filtered_arp_packets = []
    communications = []
    complete_comms = []
    incomplete_comms = []

    # Vyfiltrujem si len REQUEST a REPLY packety
    for packet in arp_packets:
        hexdump = packet.hexa_frame.split()
        opcode = hexdump[21]
        if opcode == "01":
            packet.arp_opcode = "REQUEST"
            filtered_arp_packets.append(packet)
        elif opcode == "02":
            packet.arp_opcode = "REPLY"
            filtered_arp_packets.append(packet)

    # Zgrupím packety do komunikácii
    for frame in filtered_arp_packets:
        is_new_comm = 1
        for comm in communications:
            if (frame.arp_opcode == "REQUEST" and frame.dst_ip == comm.source_ip) or (frame.arp_opcode == "REPLY" and frame.src_ip == comm.source_ip):
                comm.add_packet(frame)
                is_new_comm = 0
                break

        if is_new_comm == 1:
            if frame.arp_opcode == "REQUEST":
                comm = Communication(0, frame.dst_ip, None, None, None, 0, packet_list=[])
            else:
                comm = Communication(0, frame.src_ip, None, None, None, 0, packet_list=[])
            comm.add_packet(frame)
            communications.append(comm)

    complete_counter = 1
    incomplete_counter = 1
    for comm in communications:
        request_packets = []
        reply_packets = []

        for packet in comm.packet_list:
            if packet.arp_opcode == "REQUEST":
                request_packets.append(packet)
            elif packet.arp_opcode == "REPLY":
                reply_packets.append(packet)

        all_packets = comm.packet_list
        comm.packet_list = []

        paired_packets = []
        paired_reply_nums = []

        # Hľadám páry request - reply
        for req_packet in request_packets:
            for reply_packet in reply_packets:
                if (req_packet.dst_ip == reply_packet.src_ip and reply_packet.dst_ip == req_packet.src_ip) and reply_packet.frame_number not in paired_reply_nums:
                    paired_packets.append(req_packet)
                    paired_packets.append(reply_packet)
                    paired_reply_nums.append(reply_packet.frame_number)
                    break

        # Párované packety dáme preč z listu pre neskoršie určovanie kompletnosti
        for packet in paired_packets:
            if packet in all_packets:
                all_packets.remove(packet)

        # Párované packety vrátime spať ku komunikácii
        for packet in paired_packets:
            comm.packet_list.append(packet)

        # Určenie nekompletnej komunikácie
        if len(all_packets) > 0:
            incomplete_comm = comm
            incomplete_comm.packet_list = []
            for packet in all_packets:
                incomplete_comm.packet_list.append(packet)

            incomplete_comm.number_comm = incomplete_counter
            incomplete_comm = incomplete_comm.arp_comm()
            incomplete_counter += 1
            incomplete_comms.append(incomplete_comm)

        # Určenie kompletnej komunikácie
        if (len(all_packets)) == 0 or (len(all_packets) > 0 and len(paired_packets) > 0):
            comm.number_comm = complete_counter
            for packet in all_packets:
                if packet in all_packets:
                    comm.packet_list.remove(packet)
            if len(all_packets) > 0:
                for packet in paired_packets:
                    comm.packet_list.append(packet)
            comm = comm.arp_comm()
            complete_counter += 1
            complete_comms.append(comm)

    yaml_filename = 'packets_arp.yaml'

    yaml_data = {
        'name': 'PKS2023/24',
        'pcap_name': pcap_filename,
        'filter_name': "ARP",
        'complete_comms': complete_comms,
        'partial_comms': incomplete_comms
    }

    with open(yaml_filename, 'w') as yaml_file:
        yaml = ruamel.yaml.YAML()
        yaml.dump(yaml_data, yaml_file)


#Základná funkcia, ktorá prečíta bajty z pcap súboru, konvertuje ich do hex podoby a následne rozdeľuje ďalej do atrubútov rámca
def analyze_all(packets,  frame_number, packet_frames, ip_add_senders, ip_address_counter, tcp_packets, udp_packets, icmp_packets, arp_packets):
    for packet in packets:
        data_in_bytes = bytes(packet)
        ISL_header_check_hex = data_in_bytes[0:5].hex()
        if ISL_header_check_hex == "01000c0000" or ISL_header_check_hex == "0c000c0000":
            # Sledujeme či má rámec ISL header, ak áno posúvame sa o jeho celú dĺžku
            data_in_bytes = data_in_bytes[26:]

        # Získanie typu rámca - Ethernet II, IEEE 802.3 LLC & SNAP, IEEE 802.3 LLC
        frame_type_result = frame_type(data_in_bytes)

        frame = Packet(frame_number=frame_number, len_frame_pcap=len(packet), len_frame_medium=frame_length_medium(packet),
                       frame_type=frame_type_result, src_mac=mac_address_format(data_in_bytes[6:12].hex()),
                       dst_mac=mac_address_format(data_in_bytes[0:6].hex()),
                       hexa_frame=LiteralScalarString(print_hex_dump(packet)))

        if frame_type_result == "ETHERNET II":
            ethertypes = get_data_from_file("Protocols/ETHERTYPE.txt")
            # Na základe bytov 13 a 14 určíme ethertype
            frame_part3_hex = data_in_bytes[12:14].hex().upper()
            frame_part3_string = "0x" + frame_part3_hex
            ethertype_name = ethertypes.get(frame_part3_string, "Unknown type")
            frame.ether_type = ethertype_name

            if ethertype_name not in ["LLDP", "IPv6", "Unknown type"]:
                source_ip = data_in_bytes[26:30].hex()
                frame.src_ip = hex_pairs_to_ip(source_ip)
                dest_ip = data_in_bytes[30:34].hex()
                frame.dst_ip = hex_pairs_to_ip(dest_ip)

            if ethertype_name == "ARP":
                arp_packets.append(frame)
                source_ip = data_in_bytes[28:32].hex()
                frame.src_ip = hex_pairs_to_ip(source_ip)
                dest_ip = data_in_bytes[38:42].hex()
                frame.dst_ip = hex_pairs_to_ip(dest_ip)

            if ethertype_name == "IPv4":
                protocols = get_data_from_file("Protocols/IP_PROTOCOLS.txt")
                # Na základe bytu 24 určíme IPv4 protocol
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

                if protocol_name == "TCP" or protocol_name == "UDP":
                    source_port = data_in_bytes[34:36].hex()
                    source_port_decimal = int(source_port, 16)
                    frame.src_port = source_port_decimal
                    dest_port = data_in_bytes[36:38].hex()
                    dest_port_decimal = int(dest_port, 16)
                    frame.dst_port = dest_port_decimal

                    if protocol_name == "TCP":
                        tcp_server_ports = get_data_from_file("Protocols/TCP.txt")
                        # Na základe portov TCP určíme well-known server ports
                        if str(source_port_decimal) in tcp_server_ports:
                            frame.app_protocol = tcp_server_ports.get(str(source_port_decimal))
                        elif frame.app_protocol is None and str(dest_port_decimal) in tcp_server_ports:
                            frame.app_protocol = tcp_server_ports.get(str(dest_port_decimal))
                        tcp_packets.append(frame)

                    elif protocol_name == "UDP":
                        udp_server_ports = get_data_from_file("Protocols/UDP.txt")
                        # Na základe portov UDP určíme well-known server ports
                        if str(source_port_decimal) in udp_server_ports:
                            frame.app_protocol = udp_server_ports.get(str(source_port_decimal))
                        elif frame.app_protocol is None and str(dest_port_decimal) in udp_server_ports:
                            frame.app_protocol = udp_server_ports.get(str(dest_port_decimal))
                        udp_packets.append(frame)

                if protocol_name == "ICMP":
                    # Určenie atribútov pre ICMP rámce
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

    # Výpis IP odosielateľov packetov
    for node, packets_sent in ip_add_senders.items():
        ipv4_sender = IPv4_sender(node, packets_sent)
        ipv4_dict = {k: v for k, v in ipv4_sender.__dict__.items() if v is not None}
        ip_address_counter.append(ipv4_dict)

    # Uzol/uzly kt. odoslal najviac packetov
    max_senders = find_max_senders(ip_address_counter)

    yaml_data = {
        'name': 'PKS2023/24',
        'pcap_name': pcap_filename,
        'packets': packet_frames,
        'ipv4_senders': ip_address_counter,
        'max_sent_packets_by': max_senders,
    }

    with open(yaml_filename, 'w') as yaml_file:
        yaml = ruamel.yaml.YAML()
        yaml.dump(yaml_data, yaml_file)

# Menu pre užívateľa:
if __name__ == "__main__":
    yaml_filename = 'packets_all.yaml'
    pcap_filename = input("Zadajte cestu súboru na analýzu so súborom v tvare názovsúboru.pcap:")
    packets = rdpcap(pcap_filename)
    frame_number = 1
    packet_frames = []
    ip_add_senders = {}
    ip_address_counter = []
    tcp_packets = []
    udp_packets = []
    icmp_packets = []
    arp_packets = []

    analyze_all(packets, frame_number, packet_frames, ip_add_senders, ip_address_counter, tcp_packets,
                udp_packets, icmp_packets, arp_packets)

    print()
    print("*----------------------------------------------------------------------------*")
    print("|                      Analyzátor sieťovej komunikácie                       |")
    print("|                           Autor: Petra Miková                              |")
    print("*----------------------------------------------------------------------------*")
    print()
    print("-----------------------------------GUIDE--------------------------------------")
    print("HTTP - výpis HTTP komunikácii")
    print("HTTPS - výpis HTTPS komunikácii")
    print("TELNET - výpis TELNET komunikácii")
    print("SSH - výpis SSH komunikácii")
    print("FTP-CONTROL - výpis FTP riadiaci protokol komunikácii")
    print("FTP-DATA - výpis FTP dátový protokol komunikácii")
    print("TFTP - pre výpis TFTP komunikácii")
    print("ICMP - pre výpis ICMP komunikácii")
    print("ARP - pre výpis ARP komunikácii")
    print()

    while True:
        user_input = input("Zadajte filter (skratku protokolu):")

        if user_input == "HTTP" or user_input == "HTTPS" or user_input == "TELNET" or user_input == "SSH" or user_input == "FTP-CONTROL" or user_input == "FTP-DATA":
            filtered = filter_tcp_comms(tcp_packets, user_input)
            grouped = group_comms(filtered)
            list_tcp = analyze_completeness_of_comm(grouped)
            distinguish_tcp_comms(list_tcp)
            break
        elif user_input == "TFTP":
            distinguish_tftp_comms(tftp_comms(udp_packets))
            break
        elif user_input == "ICMP":
            icmp_comms(icmp_packets)
            break
        elif user_input == "ARP":
            arp_comms(arp_packets)
            break
        else:
            red = "\033[91m"
            reset = "\033[0m"
            text = "Nesprávny vstup."
            print(red + text + reset)