def parse_sublist3r(text_file):
    try:
        with open(text_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        return subdomains
    except FileNotFoundError:
        return []
