def parse_httpx(text_file):
    parsed_data = {}
    try:
        with open(text_file, 'r') as f:
            content = f.read()
            lines = content.splitlines()
            
            # Extract status line (e.g., HTTP/1.1 200 OK)
            if lines:
                parsed_data['status_line'] = lines[0].strip()
                
            # Extract headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
                elif not line.strip(): # Stop at first empty line after headers
                    break
            parsed_data['headers'] = headers
            
    except Exception as e:
        print(f"Error parsing httpx output file {text_file}: {e}")
    return parsed_data