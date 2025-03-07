import json
import sys
import re
from typing import Dict, List, Any, Optional, Set, Tuple


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


def load_existing_fortigate_config(filename: str) -> Dict[str, Dict[str, str]]:
    """
    Load existing FortiGate configuration and extract object names and types.
    Returns a dictionary with object names as keys and their details as values.
    """
    existing_objects = {}

    try:
        with open(filename, 'r') as f:
            config_content = f.read()

        # Extract address objects
        # Pattern to match edit statements followed by object details
        pattern = r'edit\s+"([^"]+)"(.*?)next'
        matches = re.findall(pattern, config_content, re.DOTALL)

        for match in matches:
            object_name = match[0]
            object_details = match[1].strip()

            # Extract type information
            type_match = re.search(r'set\s+type\s+(\w+)', object_details)
            obj_type = type_match.group(1) if type_match else "unknown"

            # Extract IP information based on object type
            ip_info = {}
            if obj_type == "ipmask":
                subnet_match = re.search(r'set\s+subnet\s+([0-9.]+/[0-9]+)', object_details)
                if subnet_match:
                    ip_info["subnet"] = subnet_match.group(1)
            elif obj_type == "iprange":
                start_ip_match = re.search(r'set\s+start-ip\s+([0-9.]+)', object_details)
                end_ip_match = re.search(r'set\s+end-ip\s+([0-9.]+)', object_details)
                if start_ip_match:
                    ip_info["start-ip"] = start_ip_match.group(1)
                if end_ip_match:
                    ip_info["end-ip"] = end_ip_match.group(1)

            existing_objects[object_name] = {
                "type": obj_type,
                "ip_info": ip_info
            }

    except FileNotFoundError:
        print(f"Warning: Existing FortiGate config file {filename} not found. Will create all new objects.")

    return existing_objects


def convert_host_object(obj: Dict, existing_objects: Dict[str, Dict[str, str]]) -> Tuple[Optional[str], bool]:
    """
    Convert a Checkpoint host object to FortiGate format.
    Returns a tuple of (command_string, is_duplicate)
    """
    name = obj.get('name')
    ipv4_address = obj.get('ipv4-address')
    comment = obj.get('comments', '')

    if not name or not ipv4_address:
        return None, False

    # Check if this object already exists in FortiGate config
    is_duplicate = False
    if name in existing_objects:
        existing_obj = existing_objects[name]
        if existing_obj["type"] == "ipmask":
            if "subnet" in existing_obj["ip_info"] and existing_obj["ip_info"]["subnet"] == f"{ipv4_address}/32":
                is_duplicate = True

    if is_duplicate:
        return None, True

    fortigate_cmd = f"config firewall address\n"
    fortigate_cmd += f"    edit \"{name}\"\n"
    fortigate_cmd += f"        set type ipmask\n"
    fortigate_cmd += f"        set subnet {ipv4_address}/32\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd, False


def convert_network_object(obj: Dict, existing_objects: Dict[str, Dict[str, str]]) -> Tuple[Optional[str], bool]:
    """
    Convert a Checkpoint network object to FortiGate format.
    Returns a tuple of (command_string, is_duplicate)
    """
    name = obj.get('name')
    subnet4 = obj.get('subnet4')
    mask_length4 = obj.get('mask-length4')
    comment = obj.get('comments', '')

    if not name or not subnet4 or mask_length4 is None:
        return None, False

    # Check if this object already exists in FortiGate config
    is_duplicate = False
    if name in existing_objects:
        existing_obj = existing_objects[name]
        if existing_obj["type"] == "ipmask":
            if "subnet" in existing_obj["ip_info"] and existing_obj["ip_info"]["subnet"] == f"{subnet4}/{mask_length4}":
                is_duplicate = True

    if is_duplicate:
        return None, True

    fortigate_cmd = f"config firewall address\n"
    fortigate_cmd += f"    edit \"{name}\"\n"
    fortigate_cmd += f"        set type ipmask\n"
    fortigate_cmd += f"        set subnet {subnet4}/{mask_length4}\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd, False


def convert_range_object(obj: Dict, existing_objects: Dict[str, Dict[str, str]]) -> Tuple[Optional[str], bool]:
    """
    Convert a Checkpoint address range object to FortiGate format.
    Returns a tuple of (command_string, is_duplicate)
    """
    name = obj.get('name')
    ipv4_address_first = obj.get('ipv4-address-first')
    ipv4_address_last = obj.get('ipv4-address-last')
    comment = obj.get('comments', '')

    if not name or not ipv4_address_first or not ipv4_address_last:
        return None, False

    # Check if this object already exists in FortiGate config
    is_duplicate = False
    if name in existing_objects:
        existing_obj = existing_objects[name]
        if existing_obj["type"] == "iprange":
            if ("start-ip" in existing_obj["ip_info"] and
                    "end-ip" in existing_obj["ip_info"] and
                    existing_obj["ip_info"]["start-ip"] == ipv4_address_first and
                    existing_obj["ip_info"]["end-ip"] == ipv4_address_last):
                is_duplicate = True

    if is_duplicate:
        return None, True

    fortigate_cmd = f"config firewall address\n"
    fortigate_cmd += f"    edit \"{name}\"\n"
    fortigate_cmd += f"        set type iprange\n"
    fortigate_cmd += f"        set start-ip {ipv4_address_first}\n"
    fortigate_cmd += f"        set end-ip {ipv4_address_last}\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd, False


def convert_group_object(obj: Dict, objects_by_uid: Dict, existing_objects: Dict[str, Dict[str, str]]) -> Tuple[
    Optional[str], bool]:
    """
    Convert a Checkpoint group object to FortiGate format.
    Returns a tuple of (command_string, is_duplicate)
    """
    name = obj.get('name')
    members = obj.get('members', [])
    comment = obj.get('comments', '')

    if not name or not members:
        return None, False

    # Simple check for duplicate (just by name, can't easily check members)
    if name in existing_objects:
        return None, True

    fortigate_cmd = f"config firewall addrgrp\n"
    fortigate_cmd += f"    edit \"{name}\"\n"

    # Convert member UIDs to names
    member_names = []
    for member_uid in members:
        if member_uid in objects_by_uid:
            member_obj = objects_by_uid[member_uid]
            member_name = member_obj.get('name')
            if member_name:
                member_names.append(member_name)

    if member_names:
        member_str = ' '.join(f'"{name}"' for name in member_names)
        fortigate_cmd += f"        set member {member_str}\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd, False


def convert_service_tcp_object(obj: Dict, existing_objects: Dict[str, Dict[str, str]]) -> Tuple[Optional[str], bool]:
    """
    Convert a Checkpoint TCP service object to FortiGate format.
    Returns a tuple of (command_string, is_duplicate)
    """
    name = obj.get('name')
    port = obj.get('port')
    comment = obj.get('comments', '')

    if not name or not port:
        return None, False

    # Simple check for duplicate by name
    if name in existing_objects:
        return None, True

    fortigate_cmd = f"config firewall service custom\n"
    fortigate_cmd += f"    edit \"{name}\"\n"
    fortigate_cmd += f"        set tcp-portrange {port}\n"
    fortigate_cmd += f"        set protocol TCP/UDP/SCTP\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd, False


def convert_service_udp_object(obj: Dict, existing_objects: Dict[str, Dict[str, str]]) -> Tuple[Optional[str], bool]:
    """
    Convert a Checkpoint UDP service object to FortiGate format.
    Returns a tuple of (command_string, is_duplicate)
    """
    name = obj.get('name')
    port = obj.get('port')
    comment = obj.get('comments', '')

    if not name or not port:
        return None, False

    # Simple check for duplicate by name
    if name in existing_objects:
        return None, True

    fortigate_cmd = f"config firewall service custom\n"
    fortigate_cmd += f"    edit \"{name}\"\n"
    fortigate_cmd += f"        set udp-portrange {port}\n"
    fortigate_cmd += f"        set protocol TCP/UDP/SCTP\n"

    if comment:
        fortigate_cmd += f"        set comment \"{comment}\"\n"

    fortigate_cmd += f"    next\nend"
    return fortigate_cmd, False


def convert_objects(checkpoint_data: Any, existing_objects: Dict[str, Dict[str, str]]) -> Tuple[List[str], int]:
    """
    Convert Checkpoint objects to FortiGate CLI commands.
    Returns a tuple of (fortigate_commands, skipped_count)
    """
    fortigate_commands = []
    skipped_count = 0

    # Handle the case when checkpoint_data is already a list of objects
    objects = []
    if isinstance(checkpoint_data, list):
        objects = checkpoint_data
    elif isinstance(checkpoint_data, dict) and 'objects' in checkpoint_data:
        objects = checkpoint_data.get('objects', [])

    if not objects:
        print("Warning: No objects found in the input file")
        return fortigate_commands, skipped_count

    # Create a lookup table for objects by UID
    objects_by_uid = {obj.get('uid'): obj for obj in objects if 'uid' in obj}

    # Process objects in the right order (simple objects first, then groups)
    # First, separate simple objects and group objects
    simple_objects = []
    group_objects = []

    for obj in objects:
        obj_type = obj.get('type')
        if obj_type == 'group':
            group_objects.append(obj)
        else:
            simple_objects.append(obj)

    # Process simple objects first
    for obj in simple_objects:
        obj_type = obj.get('type')
        cmd = None
        is_duplicate = False

        if obj_type == 'host':
            cmd, is_duplicate = convert_host_object(obj, existing_objects)
        elif obj_type == 'network':
            cmd, is_duplicate = convert_network_object(obj, existing_objects)
        elif obj_type == 'address-range':
            cmd, is_duplicate = convert_range_object(obj, existing_objects)
        elif obj_type == 'service-tcp':
            cmd, is_duplicate = convert_service_tcp_object(obj, existing_objects)
        elif obj_type == 'service-udp':
            cmd, is_duplicate = convert_service_udp_object(obj, existing_objects)
        # Skip unsupported object types

        if is_duplicate:
            skipped_count += 1
        elif cmd:
            fortigate_commands.append(cmd)

    # Then process group objects
    for obj in group_objects:
        cmd, is_duplicate = convert_group_object(obj, objects_by_uid, existing_objects)

        if is_duplicate:
            skipped_count += 1
        elif cmd:
            fortigate_commands.append(cmd)

    return fortigate_commands, skipped_count


def main():
    """Main function."""
    output_file = 'checkpoint-to-fortigate.txt'
    input_file = 'AUWHCEDGEvFW_Policy_objects.json'
    existing_config_file = 'Existing objects.txt'

    # Load Checkpoint objects
    checkpoint_data = load_checkpoint_objects(input_file)

    # Load existing FortiGate configuration
    print(f"Checking for existing objects in {existing_config_file}...")
    existing_objects = load_existing_fortigate_config(existing_config_file)
    print(f"Found {len(existing_objects)} existing objects in FortiGate config.")

    # Convert objects
    fortigate_commands, skipped_count = convert_objects(checkpoint_data, existing_objects)

    # Write FortiGate commands to output file
    with open(output_file, 'w') as f:
        for cmd in fortigate_commands:
            f.write(cmd + '\n\n')

    num_converted = len(fortigate_commands)
    total_objects = num_converted + skipped_count

    print(f"Processed {total_objects} Checkpoint objects:")
    print(f"  - Converted {num_converted} objects to FortiGate format")
    print(f"  - Skipped {skipped_count} objects (already exist in FortiGate config)")
    print(f"FortiGate commands written to {output_file}")


if __name__ == "__main__":
    main()