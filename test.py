import subprocess

def get_all_connected_network_details(text):
    # Initialize variables
    section_lines = []
    inside_connected_section = False
    connected_sections = []

    # Iterate over each line in the text
    for line in text.split('\n'):
        # If the line contains 'adapter', we're starting a new section
        if 'adapter' in line:
            # If we were inside a connected section, add it to the list
            if inside_connected_section:
                connected_sections.append('\n'.join(section_lines))

            # Start a new section
            section_lines = [line]
            inside_connected_section = True
        elif 'Media disconnected' in line:
            # If the line contains 'Media disconnected', mark the section as disconnected
            inside_connected_section = False
        else:
            # Otherwise, add the line to the current section
            section_lines.append(line)

    # If the last section was connected, add it to the list
    if inside_connected_section:
        connected_sections.append('\n'.join(section_lines))

    # If no connected section was found, return a message
    if not connected_sections:
        return "No connected network service found."

    return connected_sections


def get_physical_and_ipv4_address(connected_sections):
    addresses = []
    for section in connected_sections:
        lines = section.split('\n')
        physical_address = "Not available"
        ipv4_address = "Not available"
        for line in lines:
            if 'Physical Address' in line:
                physical_address = line.split(': ')[-1]
            elif 'IPv4 Address' in line:
                ipv4_address = line.split(': ')[-1].split('(Preferred)')[0]
        addresses.append((f'MAC: {physical_address.strip()}', f'IP: {ipv4_address.strip()}'))
    return addresses


network_config_text = subprocess.check_output("ipconfig /all", shell=True).decode()
connected_network_details = get_all_connected_network_details(network_config_text)
addresses = get_physical_and_ipv4_address(connected_network_details)
print(addresses)
