
import re

def parse_whatweb(text_file):
    data = {}
    try:
        with open(text_file, 'r') as f:
            content = f.read()
        # Remove ANSI escape codes
        content = re.sub(r'\x1b\[[0-9;]*m', '', content)

        # Extract URL and status code
        match_url_status = re.match(r'(https?://[^ ]+) \[([0-9]{3} [A-Z]+)\]', content)
        if match_url_status:
            data['url'] = match_url_status.group(1)
            data['status'] = match_url_status.group(2)
            content = content[match_url_status.end():].strip()

        # Split by comma and parse key[value] pairs
        pairs = content.split(', ')
        for pair in pairs:
            pair = pair.strip()
            if not pair: continue
            if '[' in pair and ']' in pair:
                key, value = pair.split('[', 1)
                value = value[:-1] # Remove closing bracket
                key = key.strip()
                value = value.strip()

                if key in data:
                    if isinstance(data[key], list):
                        data[key].append(value)
                    else:
                        data[key] = [data[key], value]
                else:
                    data[key] = value
            elif pair.strip(): # Handle cases like 'HTML5' without a value
                data[pair.strip()] = True

    except FileNotFoundError:
        print(f"WhatWeb text file not found: {text_file}")
        return {}
    except Exception as e:
        print(f"Error parsing WhatWeb text file {text_file}: {e}")
        return {}

    return data
