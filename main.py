from scapy.all import rdpcap

packets = rdpcap('trace-26.pcap')
frame_number = 1


def frame_length_medium(packet):
    if len(packet) < 60:
        length = 64  # Minimum frame length including padding and FCS
    else:
        length = len(packet) + 4  # Add FCS at the end

    return length


def pretty_print_hex_string(packet):
    hex_string = bytes(packet).hex()

    formatted_string = ''

    # Iterate through the hex string
    for i in range(0, len(hex_string), 2):
        formatted_string += hex_string[i:i + 2] + ' '  # Add two characters and a space

        # Break line after every 16 pairs of characters
        if (i + 2) % 32 == 0:
            formatted_string += '\n'

    return formatted_string


def mac_address_format(mac_address):
    string_mac = str(mac_address)
    upper_str = string_mac.upper()

    formatted_mac = ''

    for i in range(0, len(upper_str), 2):
        formatted_mac += upper_str[i:i + 2] + ':'

    return formatted_mac[:-1]


def frame_type(data_in_bytes):
    frame_part3_hex = data_in_bytes[12:14].hex()
    part_check_raw = data_in_bytes[14:16].hex()
    part_check_snap = data_in_bytes[14:15].hex()

    decimal_part3_length = int(frame_part3_hex, 16)

    if decimal_part3_length > 1500:
        frame_type_string = "Ethernet II"
        print(f"Frame type: {frame_type_string}")

    else:
        if part_check_raw == "ffff":
            frame_type_string = "RAW"
            print(f"Frame type: {frame_type_string}")
        elif part_check_snap == "aa":
            frame_type_string = "LLC SNAP"
            print(f"Frame type: {frame_type_string}")
            pids = get_data_from_file("PID.txt")
            frame_pid_hex = data_in_bytes[20:22].hex()
            frame_pid_string = "0x" + frame_pid_hex
            pid_name = pids.get(frame_pid_string, "Unknown type")
            print(f"PID for LLC SNAP type: {pid_name}")
        else:
            frame_type_string = "LLC"
            print(f"Frame type: {frame_type_string}")
            saps = get_data_from_file("LLC.txt")
            frame_sap_hex = data_in_bytes[14:15].hex()
            frame_sap_string = "0x" + frame_sap_hex
            sap_name = saps.get(frame_sap_string, "Unknown type")
            print(f"SAP for LLC type: {sap_name}")


def get_data_from_file(file_string):
    data = {}
    with open(file_string, "r") as file:
        for line in file:
            # Split the line at the first space character
            parts = line.strip().split(' ', 1)
            if len(parts) == 2:
                hex = parts[0]
                name = parts[1]
                data[hex] = name

    return data


for packet in packets:
    frame_length = len(packet)
    frame_len_w_FCS = frame_length_medium(packet)
    data_in_bytes = bytes(packet)
    ISL_header_check_hex = data_in_bytes[0:5].hex()
    if ISL_header_check_hex == "01000c0000" or ISL_header_check_hex == "0c000c0000":
        print(f"Frame has ISL header")
        data_in_bytes = data_in_bytes[26:]
    print(f"Frame number: {frame_number}")
    print(f"Frame Length: {frame_length} bytes")
    print(f"Media Length: {frame_len_w_FCS} bytes")
    frame_type(data_in_bytes)

    dst_mac_hex = data_in_bytes[0:6].hex()
    src_mac_hex = data_in_bytes[6:12].hex()

    print(f"Destination MAC address: {mac_address_format(dst_mac_hex)}")
    print(f"Source MAC address: {mac_address_format(src_mac_hex)}")
    print("Hex dump:")
    print(pretty_print_hex_string(packet))
    print(f"_________________________________________________")

    frame_number += 1
