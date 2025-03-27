import csv
import sys

    
def convert_lookup(lookup):
    """
    Load tag mappings from CSV file.
    Handles case-insensitive mappings.
    """
    lookup_dict = {}
    
    try:
        with open(lookup, 'r') as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                if len(row) == 3:
                    dest = row[0].strip().lower()
                    protocol = row[1].strip().lower()
                    tag = row[2].strip().lower()
                    # Make key a tuple of destination port and protocol and value the tag string
                    key = (dest, protocol) 
                    lookup_dict[key] = tag
                else:
                    print(f"Skipping malformed row in lookup file: {row}")
    except FileNotFoundError:
        print(f"Lookup file not found: {lookup}")
        return {}
    except Exception as e:
        print(f"An error occurred while reading lookup file: {e}")
        return {}
    return lookup_dict

def get_counts(lookup, flow_logs):
    PROTOCOL_MAP = {
    '0': 'hopopt',    # Hop-by-Hop Option
    '1': 'icmp',      # Internet Control Message Protocol
    '6': 'tcp',       # Transmission Control Protocol
    '17': 'udp',      # User Datagram Protocol
    '47': 'gre',      # Generic Routing Encapsulation
    '50': 'esp',      # Encapsulating Security Payload
    '58': 'icmpv6' # ICMPv6
}
    
    tag_counts = {}
    combo_counts = {}
    lookup_dict = convert_lookup(lookup)
    try:
        with open(flow_logs, 'r') as f:
            for line in f:
                # Parse log line
                parts = line.strip().split()
                if len(parts) < 8:
                        print(f"Skipping row with insufficient data: {line}")
                        continue
                dest = parts[5].lower()
                protocol_num = parts[7].lower()
                protocol = PROTOCOL_MAP[protocol_num] if PROTOCOL_MAP.get(protocol_num) else protocol_num # If protocol number doesn't correspond, just leave it as its number so it goes untagged
                # map line to tag
                if (dest, protocol) in lookup_dict:
                    mapping = lookup_dict[(dest, protocol)]
                elif ("0", protocol) in lookup_dict:
                    mapping = lookup_dict[(dest, protocol)]
                else:
                    mapping = "Untagged"

                tag_counts[mapping] = tag_counts.get(mapping, 0) + 1
                # Port/protocol combination counts update
                combo_counts[(dest, protocol)] = combo_counts.get((dest, protocol), 0) + 1
    except FileNotFoundError:
        print(f"Flow log file not found: {flow_logs}")
        return {}, {}
    except Exception as e:
        print(f"An error occurred while reading flow log file: {e}")
        return {}, {}
    return tag_counts, combo_counts

def write_counts(tag_counts, combo_counts):
    try:
        with open("output.txt", 'w', newline='') as f:
            f.write("Tag Counts:\nTag,Count\n")
            for tag, count in tag_counts.items():
                f.write(f"{tag},{count}\n")
            f.write("\nPort/Protocol Combination Counts:\nPort,Protocol,Count\n")
            for (port, protocol), count in combo_counts.items():
                f.write(f"{port},{protocol},{count}\n")
    except Exception as e:
        print(f"An error occurred while writing output file: {e}")
    return "output.txt"

def check_flow_log_version(flow_log_file):
    """
    Check the version of the flow log.
    """
    
    with open(flow_log_file, 'r') as f:
        # Assuming the version is mentioned in the first line of the file
        version_line = f.readline().strip()
        return int(version_line.split()[0])


def main():
    if len(sys.argv) != 3:
        print("Incorrect amount of arguments")
        return
    # Command line args
    lookup = sys.argv[1]
    flow_logs = sys.argv[2]
    #log_format = sys.argv[4] #contains info about if format of file is default or custom
    tag_counts, combo_counts = get_counts(lookup, flow_logs)
    if tag_counts and combo_counts:
        write_counts(tag_counts, combo_counts)
    else:
        print("No data to write.")




if __name__ == "__main__":
    main()
