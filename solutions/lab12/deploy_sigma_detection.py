#!/usr/bin/env python3
"""
Script to deploy Sigma detection rules to Splunk.

This script takes a YAML file containing a Sigma detection rule as input,
converts it to a Splunk search query using the DetectionDeployer class,
and deploys it as a saved search in Splunk.
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
        description='Deploy Sigma detection rules to Splunk',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python deploy_sigma_detection.py detection.yml
  python deploy_sigma_detection.py /path/to/detection.yml --host splunk.example.com
  python deploy_sigma_detection.py detection.yml --username admin --password secret --lab-host lab2
        """
    )
    
    parser.add_argument(
        'yaml_file',
        help='Path to the YAML file containing the Sigma detection rule'
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
    
    # Verify YAML file exists
    if not os.path.exists(args.yaml_file):
        print(f"Error: File '{args.yaml_file}' does not exist.")
        sys.exit(1)
    
    # Load and validate Sigma detection
    print(f"Loading Sigma detection from: {args.yaml_file}")
    sigma_detection = load_sigma_detection(args.yaml_file)
    
    if not validate_sigma_detection(sigma_detection):
        sys.exit(1)
    
    print(f"Successfully loaded Sigma detection: {sigma_detection.get('title', 'Untitled')}")
    
    # Get detection name from YAML title
    detection_name = get_detection_name(sigma_detection)
    print(f"Detection name: {detection_name}")
    
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
    
    # Convert Sigma to Splunk search
    try:
        splunk_search = deployer.sigma_to_splunk_conversion(sigma_detection)
        print(f"\nConverted Splunk search:")
        print(f"index=win host={args.lab_host} {splunk_search}")
    except Exception as e:
        print(f"Error converting Sigma detection to Splunk: {e}")
        sys.exit(1)
    
    # Deploy or show dry-run
    if args.dry_run:
        print("\nDry run mode - detection not deployed.")
        return
    
    print(f"\nDeploying detection to Splunk...")
    success = deployer.deploy_splunk_detection(sigma_detection, detection_name)
    
    if success:
        print(f"✅ Successfully deployed detection '{detection_name}' to Splunk")
        print(f"The detection is scheduled to run every 5 minutes.")
    else:
        print(f"❌ Failed to deploy detection '{detection_name}'")
        sys.exit(1)


if __name__ == "__main__":
    main()
