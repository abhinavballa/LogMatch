import csv
import sys
import concurrent.futures
#Version of my code using Concurrency

def process_chunk(chunk):

    lookup_dict = {}
    for row in chunk:
        if len(row) == 3:
            dest = row[0].strip().lower()
            protocol = row[1].strip().lower()
            tag = row[2].strip().lower()
            # Make key a tuple of destination port and protocol and value the tag string
            key = (dest, protocol) 
            lookup_dict[key] = tag
        else:
            print(f"Skipping malformed row: {row}")
    return lookup_dict

def split_file_into_chunks(file_path, chunk_size=100):

    chunks = []
    try:
        with open(file_path, 'r') as f:
            reader = csv.reader(f)
            next(reader)
            chunk = []
            for row in reader:
                chunk.append(row)
                if len(chunk) == chunk_size:
                    chunks.append(chunk)
                    chunk = []
            if chunk:
                chunks.append(chunk)
    except FileNotFoundError:
        print(f"Lookup file not found: {file_path}")
        return []
    except Exception as e:
        print(f"An error occurred while reading lookup file: {e}")
        return []
    return chunks

def convert_lookup_threads(lookup):
    chunks = split_file_into_chunks(lookup)
    combined_lookup_dict = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_chunk, chunk): chunk for chunk in chunks}
        
        for future in concurrent.futures.as_completed(futures):
            chunk = futures[future]
            try:
                lookup_dict = future.result()
            except Exception as e:
                print(f"An error occurred while processing chunk: {e}")
            else:
                combined_lookup_dict.update(lookup_dict)
    
    return combined_lookup_dict

    


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
    lookup_dict = convert_lookup_threads(lookup)
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
 #assumption that port 0 is a NOT a catch all for every log matching protocol
                else:
                    mapping = "Untagged"

                tag_counts[mapping] = tag_counts.get(mapping, 0) + 1
                # Port/protocol combination counts update
                combo_counts[(dest, protocol)] = combo_counts.get((dest, protocol), 0) + 1
    except FileNotFoundError:
        print(f"Flow log file not found: {flow_logs}")
        return {}, {}
    except Exception as e:
        print(e)
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
