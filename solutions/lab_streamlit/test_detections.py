#!/usr/bin/env python3

import os
import sys
import yaml
import argparse
import glob
from pathlib import Path
from detection_testing_manager import DetectionTestingManager


def load_environment_variables():
    """Load required environment variables for Splunk connection."""
    required_vars = ['SPLUNK_HOST', 'SPLUNK_USERNAME', 'SPLUNK_PASSWORD']
    env_vars = {}
    
    for var in required_vars:
        value = os.environ.get(var)
        if not value:
            raise ValueError(f"Environment variable {var} is required but not set")
        env_vars[var.lower().replace('splunk_', '')] = value
    
    return env_vars


def find_yaml_files(folder_path):
    """Find all YAML files in the specified folder."""
    folder = Path(folder_path)
    if not folder.exists():
        raise FileNotFoundError(f"Folder {folder_path} does not exist")
    
    if not folder.is_dir():
        raise NotADirectoryError(f"{folder_path} is not a directory")
    
    # Find all .yml and .yaml files
    yaml_files = []
    yaml_files.extend(glob.glob(str(folder / "*.yml")))
    yaml_files.extend(glob.glob(str(folder / "*.yaml")))
    
    if not yaml_files:
        print(f"Warning: No YAML files found in {folder_path}")
    
    return yaml_files


def load_sigma_detection(file_path):
    """Load and parse a sigma detection YAML file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            detection_data = yaml.safe_load(file)
        return detection_data
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file {file_path}: {e}")
        return None
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None


def test_detection(detection_manager, detection_data, file_name, file_path, 
                   skip_cleanup=False):
    """Test a single detection using the DetectionTestingManager."""
    print(f"\n--- Testing detection: {file_name} ---")
    
    try:
        # Check if detection has data file to send
        data_file = detection_data.get('data')
        source = detection_data.get('source', 'test')
        sourcetype = detection_data.get('sourcetype', 'test')
        
        if data_file:
            # Construct data file path relative to detection file
            detection_dir = Path(file_path).parent
            data_file_path = detection_dir / data_file
            
            if not data_file_path.exists():
                print(f"❌ Data file not found: {data_file_path}")
                return False
            
            print(f"📤 Sending attack data from: {data_file}")
            
            # Send attack data to Splunk
            detection_manager.send_attack_data(
                file_path=str(data_file_path),
                source=source,
                sourcetype=sourcetype,
                host=detection_manager.conn.host  # Use the Splunk host
            )
            print("✅ Attack data sent successfully")
            
            # Wait a moment for data to be indexed
            import time
            time.sleep(3)
        
        # Convert sigma detection to Splunk search
        splunk_search = detection_manager.sigma_to_splunk_conversion(detection_data)
        print(f"Generated Splunk search: {splunk_search}")
        
        # Run the detection
        result = detection_manager.run_detection(splunk_search)
        
        if result:
            print(f"✅ Detection {file_name} triggered successfully")
            detection_result = True
        else:
            print(f"❌ Detection {file_name} did not trigger")
            detection_result = False
        
        # Clean up attack data after testing (unless skip_cleanup is True)
        if data_file and not skip_cleanup:
            print("🧹 Cleaning up attack data...")
            detection_manager.delete_attack_data()
            print("✅ Attack data cleaned up")
        
        return detection_result
            
    except Exception as e:
        print(f"❌ Error testing detection {file_name}: {e}")
        # Try to clean up data even if there was an error (unless skip_cleanup)
        try:
            if detection_data.get('data') and not skip_cleanup:
                detection_manager.delete_attack_data()
                print("✅ Attack data cleaned up after error")
        except Exception:
            pass
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Test sigma detection rules using Splunk",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables Required:
  SPLUNK_HOST      - Splunk server hostname/IP
  SPLUNK_USERNAME  - Splunk username
  SPLUNK_PASSWORD  - Splunk password

Example usage:
  python test_detections.py /path/to/detections/folder
  
  # Skip automatic cleanup
  python test_detections.py --no-cleanup /path/to/detections/folder
  
  # Set environment variables first:
  export SPLUNK_HOST="192.168.1.100"
  export SPLUNK_USERNAME="admin" 
  export SPLUNK_PASSWORD="password"
  
Note: Attack data is automatically sent and cleaned up for each detection.
      Use --no-cleanup to preserve test data in Splunk for analysis.
        """
    )
    
    parser.add_argument(
        'folder_path',
        help='Path to folder containing sigma detection YAML files'
    )
    
    parser.add_argument(
        '--no-cleanup',
        action='store_true',
        help='Skip automatic cleanup of test data after each detection'
    )
    
    args = parser.parse_args()
    
    try:
        # Load environment variables
        print("Loading environment variables...")
        env_vars = load_environment_variables()
        print(f"Connecting to Splunk host: {env_vars['host']}")
        
        # Initialize DetectionTestingManager
        detection_manager = DetectionTestingManager(
            host=env_vars['host'],
            username=env_vars['username'],
            password=env_vars['password']
        )
        
        # Configure HEC
        print("Configuring HTTP Event Collector...")
        detection_manager.configure_hec()
        print("HEC configured successfully")
        
        # Find YAML files
        print(f"\nSearching for YAML files in: {args.folder_path}")
        yaml_files = find_yaml_files(args.folder_path)
        print(f"Found {len(yaml_files)} YAML files")
        
        # Test each detection
        successful_tests = 0
        failed_tests = 0
        
        for yaml_file in yaml_files:
            file_name = Path(yaml_file).name
            print(f"\nLoading detection from: {file_name}")
            
            detection_data = load_sigma_detection(yaml_file)
            if detection_data is None:
                print(f"❌ Skipping {file_name} due to loading errors")
                failed_tests += 1
                continue
            
            # Test the detection
            if test_detection(detection_manager, detection_data, file_name, 
                              yaml_file, args.no_cleanup):
                successful_tests += 1
            else:
                failed_tests += 1
        
        # Summary
        print(f"\n{'='*50}")
        print("DETECTION TESTING SUMMARY")
        print(f"{'='*50}")
        print(f"Total detections tested: {len(yaml_files)}")
        print(f"Successful: {successful_tests}")
        print(f"Failed: {failed_tests}")
        success_rate = (successful_tests/len(yaml_files)*100 
                        if yaml_files else 0)
        print(f"Success rate: {success_rate:.1f}%")
        
        # Note about cleanup
        if args.no_cleanup:
            print("\n⚠️  Test data was not cleaned up (--no-cleanup flag used)")
            print("   You may want to manually clean up test data in Splunk")
        
        # Exit with appropriate code
        sys.exit(0 if failed_tests == 0 else 1)
        
    except KeyboardInterrupt:
        print("\n\nTesting interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
