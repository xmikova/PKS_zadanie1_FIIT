# Autor: Petra Miková
# Aktuálna verzia programu obsahuje iba riešenie úlohy 1

from scapy.all import rdpcap
import ruamel.yaml
from ruamel.yaml.scalarstring import LiteralScalarString


class Packet:
    def __init__(self, frame_number, frame_length, media_length, frame_type,
                 destination_mac_address, source_mac_address, hex_dump,
                 frame_pid=None, frame_sap=None):
        self.frame_number = frame_number
        self.frame_length = frame_length
        self.media_length = media_length
        self.frame_type = frame_type
        self.destination_mac_address = destination_mac_address
        self.source_mac_address = source_mac_address
        self.frame_pid = frame_pid
        self.frame_sap = frame_sap
        self.hex_dump = hex_dump


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

    formatted_string = ''

    for i in range(0, len(hex_string), 2):
        formatted_string += hex_string[i:i + 2] + ' '

        if (i + 2) % 32 == 0:
            formatted_string += '\n'

    if len(hex_string) % 16 == 0:
        return formatted_string
    else:
        return formatted_string + "\n"


# Funkcia pre správny formát výpisu MAC adries
def mac_address_format(mac_address):
    string_mac = str(mac_address)
    upper_str = string_mac.upper()

    formatted_mac = ''

    for i in range(0, len(upper_str), 2):
        formatted_mac += upper_str[i:i + 2] + ':'

    return formatted_mac[:-1]


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


# Funkcia pre získanie údajov pre ďalšiu analýzu z externých súborov
def get_data_from_file(file_string):
    data = {}
    with open(file_string, "r") as file:
        for line in file:
            # Split the line at the first space character
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

    frame = Packet(
        frame_number=frame_number,
        frame_length=len(packet),
        media_length=frame_length_medium(packet),
        frame_type=frame_type_result,
        destination_mac_address=mac_address_format(data_in_bytes[0:6].hex()),
        source_mac_address=mac_address_format(data_in_bytes[6:12].hex()),
        hex_dump=LiteralScalarString(print_hex_dump(packet))
    )

    if frame_type_result == "IEEE 802.3 LLC & SNAP":
        pids = get_data_from_file("PID.txt")
        frame_pid_hex = data_in_bytes[20:22].hex()
        frame_pid_string = "0x" + frame_pid_hex
        pid_name = pids.get(frame_pid_string, "Unknown type")
        frame.frame_pid = pid_name

    if frame_type_result == "IEEE 802.3 LLC":
        saps = get_data_from_file("LLC.txt")
        frame_sap_hex = data_in_bytes[14:15].hex()
        frame_sap_string = "0x" + frame_sap_hex
        sap_name = saps.get(frame_sap_string, "Unknown type")
        frame.frame_sap = sap_name

    # Vyfiltrujeme atribúty s None value pre výpis do yamlu
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

