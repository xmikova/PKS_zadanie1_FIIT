# Autor: Petra Miková
# Aktuálna verzia programu obsahuje iba riešenie úlohy 1

from scapy.all import rdpcap
import ruamel.yaml
from ruamel.yaml.scalarstring import LiteralScalarString


class Packet:
    def __init__(self, frame_number, len_frame_pcap, len_frame_medium, frame_type,
                 src_mac, dst_mac, hexa_frame,
                 pid=None, sap=None, ether_type=None, src_ip=None, dst_ip=None, protocol=None, src_port=None, dst_port=None, app_protocol=None):
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
        self.hexa_frame = hexa_frame


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
    ip_parts = [hex_pairs[i:i+2] for i in range(0, len(hex_pairs), 2)]  # Split into pairs
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


yaml_filename = 'packets_output.yaml'
pcap_filename = input("Zadajte názov súboru na analýzu v tvare názovsúboru.pcap:")
packets = rdpcap(pcap_filename)
frame_number = 1
packet_frames = []


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
                elif protocol_name == "UDP":
                    udp_server_ports = get_data_from_file("Protocols/UDP.txt")
                    if str(source_port_decimal) in udp_server_ports:
                        frame.app_protocol = udp_server_ports.get(str(source_port_decimal))
                    elif frame.app_protocol is None and str(dest_port_decimal) in udp_server_ports:
                        frame.app_protocol = udp_server_ports.get(str(dest_port_decimal))

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


yaml_data = {
    'name': 'PKS2023/24',
    'pcap_name': pcap_filename,
    'packets': packet_frames,
}

with open(yaml_filename, 'w') as yaml_file:
    yaml = ruamel.yaml.YAML()
    yaml.dump(yaml_data, yaml_file)

