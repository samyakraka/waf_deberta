#!/usr/bin/env python3
"""
Convert parsed_requests.json to detector-compatible format
Fixes format mismatch between calibration data and real-time logs
"""

import json
from pathlib import Path

def convert_request_format(old_request):
    """Convert old format to detector format"""
    return {
        'method': old_request.get('method', 'GET'),
        'path': old_request.get('path', '/'),
        'query': old_request.get('query_params', {}),
        'headers': {
            'user-agent': old_request.get('user_agent', '-'),
            'referer': old_request.get('referer', '-'),
            'content-type': old_request.get('content_type', '-'),
            'content-length': str(old_request.get('content_length', 0)),
        },
        'body': old_request.get('request_body') if old_request.get('request_body') not in ['-', None] else None,
    }

def main():
    input_file = Path('data/parsed/parsed_requests.json')
    output_file = Path('data/parsed/calibration_data.json')
    
    print(f"Reading from: {input_file}")
    
    with open(input_file, 'r') as f:
        old_requests = json.load(f)
    
    print(f"Converting {len(old_requests)} requests...")
    
    # Convert all requests
    new_requests = [convert_request_format(req) for req in old_requests]
    
    # Save converted data
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(new_requests, f, indent=2)
    
    print(f"✓ Saved {len(new_requests)} converted requests to: {output_file}")
    
    # Show sample comparison
    print("\n" + "="*80)
    print("Sample Conversion:")
    print("="*80)
    print("\nOLD FORMAT:")
    print(json.dumps(old_requests[0], indent=2))
    print("\nNEW FORMAT:")
    print(json.dumps(new_requests[0], indent=2))

if __name__ == '__main__':
    main()
