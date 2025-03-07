import json
import sys
from typing import Dict, List, Any, Optional


def load_checkpoint_objects(filename: str) -> Any:
    """Load Checkpoint objects from JSON file."""
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError:
        print(f"Error: {filename} is not a valid JSON file")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
        sys.exit(1)


def convert_host_object(obj: Dict) -> Optional[str]:
    """Convert a Checkpoint host object to FortiGate format."""
    name = obj.get('name')
    ipv4_address = obj.get('ipv4-address')
    comment = obj.get('comments', '')

    if not name or not ipv4_address:
        return None

    fortigate_cmd = f"config firewall address\n"
    fortigate_cmd += f"    edit \"{name}\"\n"
    fortigate_cmd += f"        set type ipmask\n"
    fortigate_cmd += f"        set subnet {ipv4_address}/32\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd


def convert_network_object(obj: Dict) -> Optional[str]:
    """Convert a Checkpoint network object to FortiGate format."""
    name = obj.get('name')
    subnet4 = obj.get('subnet4')
    mask_length4 = obj.get('mask-length4')
    comment = obj.get('comments', '')

    if not name or not subnet4 or mask_length4 is None:
        return None

    fortigate_cmd = f"config firewall address\n"
    fortigate_cmd += f"    edit \"{name}\"\n"
    fortigate_cmd += f"        set type ipmask\n"
    fortigate_cmd += f"        set subnet {subnet4}/{mask_length4}\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd


def convert_range_object(obj: Dict) -> Optional[str]:
    """Convert a Checkpoint address range object to FortiGate format."""
    name = obj.get('name')
    ipv4_address_first = obj.get('ipv4-address-first')
    ipv4_address_last = obj.get('ipv4-address-last')
    comment = obj.get('comments', '')

    if not name or not ipv4_address_first or not ipv4_address_last:
        return None

    fortigate_cmd = f"config firewall address\n"
    fortigate_cmd += f"    edit \"{name}\"\n"
    fortigate_cmd += f"        set type iprange\n"
    fortigate_cmd += f"        set start-ip {ipv4_address_first}\n"
    fortigate_cmd += f"        set end-ip {ipv4_address_last}\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd


def convert_group_object(obj: Dict, objects_by_uid: Dict) -> Optional[str]:
    """Convert a Checkpoint group object to FortiGate format."""
    name = obj.get('name')
    members = obj.get('members', [])
    comment = obj.get('comments', '')

    if not name or not members:
        return None

    fortigate_cmd = f"config firewall addrgrp\n"
    fortigate_cmd += f"    edit \"{name}\"\n"

    # Convert member UIDs to names
    member_names = []
    for member_uid in members:
        if member_uid in objects_by_uid:
            member_obj = objects_by_uid[member_uid]
            member_names.append(member_obj.get('name'))

    if member_names:
        member_str = ' '.join(f'"{name}"' for name in member_names)
        fortigate_cmd += f"        set member {member_str}\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd


def convert_service_tcp_object(obj: Dict) -> Optional[str]:
    """Convert a Checkpoint TCP service object to FortiGate format."""
    name = obj.get('name')
    port = obj.get('port')
    comment = obj.get('comments', '')

    if not name or not port:
        return None

    fortigate_cmd = f"config firewall service custom\n"
    fortigate_cmd += f"    edit \"{name}\"\n"
    fortigate_cmd += f"        set tcp-portrange {port}\n"
    fortigate_cmd += f"        set protocol TCP/UDP/SCTP\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd


def convert_service_udp_object(obj: Dict) -> Optional[str]:
    """Convert a Checkpoint UDP service object to FortiGate format."""
    name = obj.get('name')
    port = obj.get('port')
    comment = obj.get('comments', '')

    if not name or not port:
        return None

    fortigate_cmd = f"config firewall service custom\n"
    fortigate_cmd += f"    edit \"{name}\"\n"
    fortigate_cmd += f"        set udp-portrange {port}\n"
    fortigate_cmd += f"        set protocol TCP/UDP/SCTP\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd


def convert_objects(checkpoint_data: Any) -> List[str]:
    """Convert Checkpoint objects to FortiGate CLI commands."""
    fortigate_commands = []

    # Handle the case when checkpoint_data is already a list of objects
    objects = []
    if isinstance(checkpoint_data, list):
        objects = checkpoint_data
    elif isinstance(checkpoint_data, dict) and 'objects' in checkpoint_data:
        objects = checkpoint_data.get('objects', [])

    if not objects:
        print("Warning: No objects found in the input file")
        return fortigate_commands

    # Create a lookup table for objects by UID
    objects_by_uid = {obj.get('uid'): obj for obj in objects if 'uid' in obj}

    # Process objects in the right order (simple objects first, then groups)
    for obj in objects:
        obj_type = obj.get('type')

        if obj_type == 'host':
            cmd = convert_host_object(obj)
        elif obj_type == 'network':
            cmd = convert_network_object(obj)
        elif obj_type == 'address-range':
            cmd = convert_range_object(obj)
        elif obj_type == 'service-tcp':
            cmd = convert_service_tcp_object(obj)
        elif obj_type == 'service-udp':
            cmd = convert_service_udp_object(obj)
        elif obj_type == 'group':
            cmd = convert_group_object(obj, objects_by_uid)
        else:
            # Skip unsupported object types
            continue

        if cmd:
            fortigate_commands.append(cmd)

    return fortigate_commands


def main():
    """Main function."""
    output_file = 'checkpoint-to-fortigate.txt'
    input_file = 'AUWHCEDGEvFW_Policy_objects.json'

    # Load Checkpoint objects
    checkpoint_data = load_checkpoint_objects(input_file)

    # Convert objects
    fortigate_commands = convert_objects(checkpoint_data)

    # Write FortiGate commands to output file
    with open(output_file, 'w') as f:
        for cmd in fortigate_commands:
            f.write(cmd + '\n\n')

    num_converted = len(fortigate_commands)
    print(f"Converted {num_converted} Checkpoint objects to FortiGate format")
    print(f"FortiGate commands written to {output_file}")


if __name__ == "__main__":
    main()