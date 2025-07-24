import json
import os
from datetime import datetime
from typing import Dict, Any, List

def analyze_data_structure(data: Any, path: str = "") -> Dict[str, str]:
    """Recursively analyze data structure and return field descriptions."""
    fields = {}
    
    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            if isinstance(value, (dict, list)) and value:
                # Recursively analyze nested structures
                nested_fields = analyze_data_structure(value, current_path)
                fields.update(nested_fields)
            else:
                # Describe the field based on its type and content
                field_type = type(value).__name__
                if isinstance(value, str):
                    if "@" in value and "." in value:
                        description = f"Email address (string)"
                    elif value.startswith(("http://", "https://")):
                        description = f"URL (string)"
                    elif value.replace(".", "").replace(":", "").isdigit():
                        description = f"IP address or port (string)"
                    else:
                        description = f"Text value (string)"
                elif isinstance(value, bool):
                    description = f"Boolean flag (boolean)"
                elif isinstance(value, int):
                    description = f"Numeric value (integer)"
                elif isinstance(value, list):
                    if not value:
                        description = f"Empty list (array)"
                    else:
                        sample_type = type(value[0]).__name__ if value else "unknown"
                        description = f"Array of {sample_type} values (array)"
                else:
                    description = f"{field_type} value"
                
                fields[current_path] = description
                
    elif isinstance(data, list) and data:
        # Analyze first item as representative of the list structure
        if isinstance(data[0], dict):
            nested_fields = analyze_data_structure(data[0], path)
            fields.update(nested_fields)
    
    return fields

def categorize_fields(fields: Dict[str, str], aggregated_data: Dict[str, Any]) -> Dict[str, Dict[str, List[str]]]:
    """Categorize fields into the 5 main categories based on their source and content."""
    
    categories = {
        "Network & DNS Info": {
            "description": "Network infrastructure and DNS-related information",
            "sources": ["nmap", "dnsenum", "dnsdumpster"],
            "fields": []
        },
        "Subdomains & Hosts": {
            "description": "Discovered subdomains and host information",
            "sources": ["sublist3r", "theharvester", "dnsdumpster"],
            "fields": []
        },
        "Emails": {
            "description": "Email addresses discovered during reconnaissance",
            "sources": ["theharvester"],
            "fields": []
        },
        "Web Technologies": {
            "description": "Web technologies and frameworks detected",
            "sources": ["whatweb"],
            "fields": []
        },
        "HTTP Headers": {
            "description": "HTTP response headers and security information",
            "sources": ["httpx"],
            "fields": []
        }
    }
    
    # Categorize fields based on their source tool
    for field_path, description in fields.items():
        source_tool = field_path.split('.')[0]
        
        if source_tool in ["nmap", "dnsenum", "dnsdumpster"]:
            # Check if it's specifically subdomain/host related from dnsdumpster
            if source_tool == "dnsdumpster" and any(x in field_path.lower() for x in ["subdomain", "host", "a.", "cname"]):
                categories["Subdomains & Hosts"]["fields"].append({
                    "field": field_path,
                    "description": description,
                    "source": source_tool
                })
            else:
                categories["Network & DNS Info"]["fields"].append({
                    "field": field_path,
                    "description": description,
                    "source": source_tool
                })
                
        elif source_tool in ["sublist3r"] or (source_tool == "theharvester" and "hosts" in field_path):
            categories["Subdomains & Hosts"]["fields"].append({
                "field": field_path,
                "description": description,
                "source": source_tool
            })
            
        elif source_tool == "theharvester" and "email" in field_path.lower():
            categories["Emails"]["fields"].append({
                "field": field_path,
                "description": description,
                "source": source_tool
            })
            
        elif source_tool == "whatweb":
            categories["Web Technologies"]["fields"].append({
                "field": field_path,
                "description": description,
                "source": source_tool
            })
            
        elif source_tool == "httpx":
            categories["HTTP Headers"]["fields"].append({
                "field": field_path,
                "description": description,
                "source": source_tool
            })
        else:
            # Default categorization for uncategorized fields
            if "email" in field_path.lower():
                categories["Emails"]["fields"].append({
                    "field": field_path,
                    "description": description,
                    "source": source_tool
                })
            elif any(x in field_path.lower() for x in ["subdomain", "host", "domain"]):
                categories["Subdomains & Hosts"]["fields"].append({
                    "field": field_path,
                    "description": description,
                    "source": source_tool
                })
            else:
                categories["Network & DNS Info"]["fields"].append({
                    "field": field_path,
                    "description": description,
                    "source": source_tool
                })
    
    return categories

def generate_sample_data(aggregated_data: Dict[str, Any], max_items: int = 3) -> Dict[str, Any]:
    """Generate sample data for documentation purposes."""
    sample = {}
    
    for key, value in aggregated_data.items():
        if isinstance(value, list):
            # Take first few items for lists
            sample[key] = value[:max_items] if len(value) > max_items else value
        elif isinstance(value, dict):
            # For dictionaries, take a subset of keys
            sample_dict = {}
            for i, (k, v) in enumerate(value.items()):
                if i >= max_items:
                    sample_dict["..."] = "additional fields"
                    break
                if isinstance(v, list):
                    sample_dict[k] = v[:max_items] if len(v) > max_items else v
                else:
                    sample_dict[k] = v
            sample[key] = sample_dict
        else:
            sample[key] = value
    
    return sample

def generate_data_dictionary(domain: str, aggregated_data: Dict[str, Any]) -> str:
    """Generate a comprehensive data dictionary based on the aggregated results."""
    
    # Analyze the data structure
    fields = analyze_data_structure(aggregated_data)
    
    # Categorize fields
    categories = categorize_fields(fields, aggregated_data)
    
    # Generate sample data
    sample_data = generate_sample_data(aggregated_data)
    
    # Generate the markdown content
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    content = f"""# Data Dictionary - Security Scan Results
## Domain: {domain}
## Generated: {timestamp}

---

## Overview
This data dictionary describes the structure and content of the security scan results for **{domain}**. The data is organized into five main categories based on the type of information and source tools.

## Data Categories

"""

    # Add each category
    for category_name, category_info in categories.items():
        if category_info["fields"]:  # Only include categories that have data
            content += f"""### {category_name}
**Description**: {category_info["description"]}  
**Primary Sources**: {", ".join(category_info["sources"])}

| Field Path | Description | Source Tool |
|------------|-------------|-------------|
"""
            for field_info in category_info["fields"]:
                content += f"| `{field_info['field']}` | {field_info['description']} | {field_info['source']} |\n"
            
            content += "\n"

    # Add data structure overview
    content += """---

## Complete Data Structure

The following shows the complete structure of the aggregated results:

```json
"""
    content += json.dumps(sample_data, indent=2)
    content += """
```

---

## Tool Sources

### Network & DNS Scanning Tools
- **nmap**: Network port scanner and service detection
- **dnsenum**: DNS enumeration and zone transfer attempts  
- **dnsdumpster**: DNS reconnaissance and subdomain discovery

### Subdomain & Host Discovery Tools
- **sublist3r**: Subdomain enumeration using OSINT
- **theharvester**: Email, subdomain and host OSINT gathering
- **dnsdumpster**: DNS record analysis for subdomains

### Email Discovery Tools
- **theharvester**: Email address harvesting from public sources

### Web Technology Detection Tools
- **whatweb**: Web application technology fingerprinting

### HTTP Analysis Tools
- **httpx**: HTTP header analysis and security assessment

---

## Data Quality Notes

"""

    # Add data quality information
    total_sources = sum(1 for key, value in aggregated_data.items() if value)
    available_sources = [key for key, value in aggregated_data.items() if value]
    
    content += f"- **Total data sources processed**: {total_sources}\n"
    content += f"- **Available data sources**: {', '.join(available_sources)}\n"
    
    if not aggregated_data.get("nmap"):
        content += "- ⚠️ **Warning**: No nmap data available - port scan may have failed\n"
    if not aggregated_data.get("whatweb"):
        content += "- ⚠️ **Warning**: No whatweb data available - web technology detection may have failed\n"
    if not aggregated_data.get("theharvester"):
        content += "- ⚠️ **Warning**: No theharvester data available - email/host discovery may have failed\n"

    content += f"""
---

## Usage Notes

1. **Empty Arrays**: Empty arrays (`[]`) indicate the tool ran but found no results
2. **Missing Keys**: Missing tool sections indicate the tool failed to run or produce output
3. **Nested Data**: Some tools produce nested data structures - refer to field paths for navigation
4. **Data Types**: All data is JSON-serializable (strings, numbers, booleans, arrays, objects)

---

*This data dictionary was automatically generated based on the actual scan results for {domain}.*
"""

    return content

def create_data_dictionary_file(domain: str, aggregated_data: Dict[str, Any], output_dir: str = "reports") -> str:
    """Create and save the data dictionary file."""
    
    # Generate the data dictionary content
    content = generate_data_dictionary(domain, aggregated_data)
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Save to file
    filename = f"data_dictionary_{domain}.md"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Data dictionary generated: {filepath}")
    return filepath

def generate_data_dictionary_from_json(json_file_path: str) -> str:
    """Generate data dictionary from an existing JSON file."""
    
    # Extract domain from filename
    filename = os.path.basename(json_file_path)
    if filename.startswith("results_") and filename.endswith(".json"):
        domain = filename[8:-5]  # Remove "results_" prefix and ".json" suffix
    else:
        domain = "unknown"
    
    # Load the JSON data
    with open(json_file_path, 'r', encoding='utf-8') as f:
        aggregated_data = json.load(f)
    
    # Generate and save the data dictionary
    output_dir = os.path.dirname(json_file_path)
    return create_data_dictionary_file(domain, aggregated_data, output_dir)

if __name__ == "__main__":
    # For testing - can be run standalone on a JSON file
    import sys
    if len(sys.argv) > 1:
        json_file = sys.argv[1]
        generate_data_dictionary_from_json(json_file)
    else:
        print("Usage: python data_dictionary_generator.py <path_to_results_json>")