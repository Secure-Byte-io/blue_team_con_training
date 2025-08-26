#!/usr/bin/env python3
"""
Script to deploy Sigma detection rules to Splunk.

This script takes a folder containing YAML files with Sigma detection rules as input,
filters for detections with status "stable", converts them to Splunk search queries 
using the DetectionDeployer class, and deploys them as saved searches in Splunk.
"""

import argparse
import yaml
import sys
import os
from pathlib import Path
from detection_deployer import DetectionDeployer


def load_sigma_detection(yaml_file_path):
    """
    Load and parse a Sigma detection rule from a YAML file.
    
    Args:
        yaml_file_path: Path to the YAML file containing the Sigma detection
        
    Returns:
        dict: Parsed Sigma detection rule
        
    Raises:
        FileNotFoundError: If the YAML file doesn't exist
        yaml.YAMLError: If the YAML file is malformed
    """
    try:
        with open(yaml_file_path, 'r', encoding='utf-8') as file:
            sigma_detection = yaml.safe_load(file)
            return sigma_detection
    except FileNotFoundError:
        print(f"Error: YAML file '{yaml_file_path}' not found.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        sys.exit(1)


def validate_sigma_detection(sigma_detection):
    """
    Validate that the loaded YAML contains required Sigma fields.
    
    Args:
        sigma_detection: Dictionary containing the parsed Sigma detection
        
    Returns:
        bool: True if valid, False otherwise
    """
    required_fields = ['title', 'detection', 'logsource']
    
    for field in required_fields:
        if field not in sigma_detection:
            print(f"Error: Missing required field '{field}' in Sigma detection")
            return False
    
    # Ensure title is not empty
    if not sigma_detection.get('title', '').strip():
        print("Error: Title field cannot be empty")
        return False
    
    return True


def discover_yaml_files(folder_path):
    """
    Discover all YAML files in the specified folder.
    
    Args:
        folder_path: Path to the folder containing YAML files
        
    Returns:
        list: List of Path objects for YAML files found
    """
    folder = Path(folder_path)
    if not folder.exists():
        print(f"Error: Folder '{folder_path}' does not exist.")
        return []
    
    if not folder.is_dir():
        print(f"Error: '{folder_path}' is not a directory.")
        return []
    
    yaml_files = []
    for pattern in ['*.yml', '*.yaml']:
        yaml_files.extend(folder.glob(pattern))
    
    return sorted(yaml_files)


def filter_stable_detections(yaml_files):
    """
    Filter YAML files to only include detections with status "stable".
    
    Args:
        yaml_files: List of Path objects to YAML files
        
    Returns:
        list: List of tuples (file_path, detection_dict) for stable detections
    """
    stable_detections = []
    
    for yaml_file in yaml_files:
        try:
            detection = load_sigma_detection(yaml_file)
            if detection.get('status') == 'stable':
                stable_detections.append((yaml_file, detection))
            else:
                print(f"Skipping {yaml_file.name} (status: {detection.get('status', 'unknown')})")
        except Exception as e:
            print(f"Error processing {yaml_file.name}: {e}")
            continue
    
    return stable_detections


def get_detection_name(sigma_detection):
    """
    Get the detection name from the Sigma detection title.
    
    Args:
        sigma_detection: Dictionary containing the parsed Sigma detection
        
    Returns:
        str: Detection name for Splunk (uses title from YAML)
    """
    return sigma_detection['title']


def main():
    """Main function to orchestrate the deployment process."""
    parser = argparse.ArgumentParser(
        description='Deploy Sigma detection rules with status "stable" to Splunk',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python deploy_sigma_detection.py /path/to/detections/
  python deploy_sigma_detection.py ./detections --host splunk.example.com
  python deploy_sigma_detection.py ./detections --username admin --password secret --lab-host lab2
        """
    )
    
    parser.add_argument(
        'folder_path',
        help='Path to the folder containing Sigma detection rule YAML files'
    )
    
    parser.add_argument(
        '--host',
        default='localhost',
        help='Splunk server host (default: localhost)'
    )
    
    parser.add_argument(
        '--username',
        default='admin',
        help='Splunk username (default: admin)'
    )
    
    parser.add_argument(
        '--password',
        default='changeme',
        help='Splunk password (default: changeme)'
    )
    
    parser.add_argument(
        '--lab-host',
        default='lab1',
        help='Lab host identifier for filtering events (default: lab1)'
    )
    

    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show the converted Splunk search without deploying'
    )
    
    args = parser.parse_args()
    
    # Discover YAML files in the folder
    print(f"Discovering YAML files in: {args.folder_path}")
    yaml_files = discover_yaml_files(args.folder_path)
    
    if not yaml_files:
        print(f"No YAML files found in '{args.folder_path}'")
        sys.exit(1)
    
    print(f"Found {len(yaml_files)} YAML files")
    
    # Filter for stable detections
    print("\nFiltering for stable detections...")
    stable_detections = filter_stable_detections(yaml_files)
    
    if not stable_detections:
        print("No stable detections found!")
        sys.exit(1)
    
    print(f"Found {len(stable_detections)} stable detections to deploy")
    
    # Initialize DetectionDeployer
    try:
        deployer = DetectionDeployer(
            host=args.host,
            username=args.username,
            password=args.password,
            lab_host=args.lab_host
        )
        print(f"Connected to Splunk at {args.host}")
    except Exception as e:
        print(f"Error connecting to Splunk: {e}")
        sys.exit(1)
    
    # Process each stable detection
    deployed_count = 0
    failed_count = 0
    
    for file_path, sigma_detection in stable_detections:
        print(f"\n--- Processing: {file_path.name} ---")
        
        # Validate detection
        if not validate_sigma_detection(sigma_detection):
            print(f"❌ Validation failed for {file_path.name}")
            failed_count += 1
            continue
        
        detection_name = get_detection_name(sigma_detection)
        print(f"Detection name: {detection_name}")
        
        # Convert Sigma to Splunk search (for display)
        try:
            splunk_search = deployer.sigma_to_splunk_conversion(sigma_detection)
            print(f"Converted Splunk search: index=win host={args.lab_host} {splunk_search[:100]}...")
        except Exception as e:
            print(f"❌ Error converting {file_path.name} to Splunk: {e}")
            failed_count += 1
            continue
        
        # Deploy or show dry-run
        if args.dry_run:
            print(f"✅ Dry run - {detection_name} would be deployed")
            deployed_count += 1
            continue
        
        # Deploy detection
        success = deployer.deploy_splunk_detection(sigma_detection, detection_name)
        
        if success:
            print(f"✅ Successfully deployed '{detection_name}'")
            deployed_count += 1
        else:
            print(f"❌ Failed to deploy '{detection_name}'")
            failed_count += 1
    
    # Summary
    print(f"\n=== Deployment Summary ===")
    print(f"Successfully deployed: {deployed_count}")
    print(f"Failed deployments: {failed_count}")
    print(f"Total stable detections: {len(stable_detections)}")
    
    if args.dry_run:
        print("Dry run mode - no detections were actually deployed.")
    elif deployed_count > 0:
        print("All deployed detections are scheduled to run every 5 minutes.")
    
    if failed_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
