import re
from collections import Counter

# Define the input log file and output file names
log_file = "failed_rdp.log.txt"
ip_file = "extracted_ips.txt"
username_file = "extracted_usernames.txt"
top_ip_file = "top_10_ips.txt"
top_username_file = "top_10_usernames.txt"

def extract_and_save(log_file):
    
    ip_pattern = r"sourcehost:([\d.]+)"
    username_pattern = r"username:([\w@.-]+)"

  
    ip_list = []
    username_list = []

    try:
        # Read the log file
        with open(log_file, "r") as file:
            for line in file:
                ip_match = re.search(ip_pattern, line)
                username_match = re.search(username_pattern, line)

                if ip_match:
                    ip_list.append(ip_match.group(1))
                if username_match:
                    username_list.append(username_match.group(1))

        # Save extracted unique data to separate files
        with open(ip_file, "w") as file:
            file.write("\n".join(set(ip_list)))

        with open(username_file, "w") as file:
            file.write("\n".join(set(username_list)))

        # Calculate top 10 most common entries
        top_ips = Counter(ip_list).most_common(10)
        top_usernames = Counter(username_list).most_common(10)

        # Save top 10 data to separate files with counts
        with open(top_ip_file, "w") as file:
            for ip, count in top_ips:
                file.write(f"{ip}: {count}\n")

        with open(top_username_file, "w") as file:
            for username, count in top_usernames:
                file.write(f"{username}: {count}\n")

        # Print summary
        print(f"Extraction complete!\n"
              f"Total unique IPs: {len(set(ip_list))}\n"
              f"Total unique usernames: {len(set(username_list))}\n"
              f"Files saved:\n"
              f"{ip_file}, {username_file}, {top_ip_file}, {top_username_file}")

    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Call the function
extract_and_save(log_file)
