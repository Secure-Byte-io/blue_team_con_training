#!/usr/bin/env python3

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path
from typing import List, Tuple

import yaml
from jsonschema import validate, ValidationError


def load_json_schema(schema_path: str) -> dict:
    """Load JSON schema from file."""
    try:
        with open(schema_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Schema file not found: {schema_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in schema file: {e}")
        sys.exit(1)


def find_yaml_files(folder_path: str) -> List[str]:
    """Find all YAML files in the specified folder."""
    folder = Path(folder_path)
    if not folder.exists():
        print(f"Error: Folder not found: {folder_path}")
        sys.exit(1)
    
    yaml_files = []
    for ext in ['*.yml', '*.yaml']:
        yaml_files.extend(folder.glob(ext))
    
    return [str(f) for f in yaml_files]


def convert_dates_to_strings(obj):
    """Recursively convert datetime.date objects to strings in YYYY-MM-DD format."""
    if isinstance(obj, date):
        return obj.strftime('%Y-%m-%d')
    elif isinstance(obj, dict):
        return {key: convert_dates_to_strings(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_dates_to_strings(item) for item in obj]
    else:
        return obj


def load_yaml_file(file_path: str) -> dict:
    """Load YAML file and return its content."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = yaml.safe_load(f)
            # Convert any date objects to strings
            return convert_dates_to_strings(content)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML syntax: {e}")
    except FileNotFoundError:
        raise ValueError(f"File not found: {file_path}")


def validate_yaml_against_schema(yaml_content: dict, schema: dict) -> Tuple[bool, str]:
    """Validate YAML content against JSON schema."""
    try:
        validate(instance=yaml_content, schema=schema)
        return True, "Valid"
    except ValidationError as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(
        description='Validate YAML detection rules against a JSON schema'
    )
    parser.add_argument(
        'rules_folder',
        help='Path to folder containing YAML detection rules'
    )
    parser.add_argument(
        'schema_file',
        help='Path to JSON schema file'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Load JSON schema
    print(f"Loading schema from: {args.schema_file}")
    schema = load_json_schema(args.schema_file)
    
    # Find YAML files
    print(f"Searching for YAML files in: {args.rules_folder}")
    yaml_files = find_yaml_files(args.rules_folder)
    
    if not yaml_files:
        print("No YAML files found in the specified folder.")
        return
    
    print(f"Found {len(yaml_files)} YAML file(s)")
    print("-" * 50)
    
    # Validate each file
    valid_count = 0
    invalid_count = 0
    
    for yaml_file in yaml_files:
        file_name = os.path.basename(yaml_file)
        print(f"Validating: {file_name}")
        
        try:
            # Load YAML content
            yaml_content = load_yaml_file(yaml_file)
            
            # Validate against schema
            is_valid, message = validate_yaml_against_schema(yaml_content, schema)
            
            if is_valid:
                print(f"  ✓ {file_name}: VALID")
                valid_count += 1
            else:
                print(f"  ✗ {file_name}: INVALID")
                if args.verbose:
                    print(f"    Error: {message}")
                invalid_count += 1
                
        except ValueError as e:
            print(f"  ✗ {file_name}: ERROR - {e}")
            invalid_count += 1
        except Exception as e:
            print(f"  ✗ {file_name}: UNEXPECTED ERROR - {e}")
            invalid_count += 1
    
    print("-" * 50)
    print(f"Summary: {valid_count} valid, {invalid_count} invalid")
    
    # Exit with error code if any files are invalid
    if invalid_count > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
