#!/usr/bin/env python3

import streamlit as st
import yaml
import tempfile
import os
import io
from pathlib import Path
from detection_testing_manager import DetectionTestingManager


def main():
    st.set_page_config(
        page_title="Sigma Detection Tester",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    st.title("🔍 Sigma Detection Testing Platform")
    st.markdown("Test your Sigma detection rules against attack data using Splunk")

    # Sidebar for configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Splunk connection settings
        st.subheader("Splunk Connection")
        
        # Check if environment variables exist, use them as defaults
        default_host = os.environ.get('SPLUNK_HOST', '')
        default_username = os.environ.get('SPLUNK_USERNAME', '')
        default_password = os.environ.get('SPLUNK_PASSWORD', '')
        
        host = st.text_input(
            "Splunk Host", 
            value=default_host,
            placeholder="192.168.1.100",
            help="Splunk server hostname or IP address"
        )
        
        username = st.text_input(
            "Username", 
            value=default_username,
            placeholder="admin",
            help="Splunk username"
        )
        
        password = st.text_input(
            "Password", 
            value=default_password,
            type="password",
            help="Splunk password"
        )
        
        # Test connection button
        if st.button("🔌 Test Connection"):
            if host and username and password:
                try:
                    with st.spinner("Testing connection..."):
                        detection_manager = DetectionTestingManager(host, username, password)
                        # Try to get Splunk info to test connection
                        info = detection_manager.conn.info
                        st.success(f"✅ Connected to Splunk {info.get('version', 'Unknown version')}")
                        st.session_state.connection_tested = True
                        st.session_state.detection_manager = detection_manager
                except Exception as e:
                    st.error(f"❌ Connection failed: {str(e)}")
                    st.session_state.connection_tested = False
            else:
                st.warning("⚠️ Please fill in all connection details")
        
        # Options
        st.subheader("Options")
        skip_cleanup = st.checkbox(
            "Skip data cleanup", 
            value=False,
            help="Keep test data in Splunk after testing (useful for debugging)"
        )

    # Main content area
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.header("📝 Sigma Detection Rule")
        
        # Show example detection structure
        with st.expander("📖 Show Example Detection", expanded=False):
            example_detection = {
                "title": "Example Detection Rule",
                "id": "12345678-1234-1234-1234-123456789abc",
                "status": "test",
                "description": "An example detection rule for demonstration",
                "author": "Security Team",
                "date": "2024-01-01",
                "tags": ["attack.execution", "attack.t1059"],
                "logsource": {
                    "category": "process_creation",
                    "product": "windows"
                },
                "detection": {
                    "selection": {
                        "Image|endswith": "\\cmd.exe",
                        "CommandLine|contains": "whoami"
                    },
                    "condition": "selection"
                },
                "falsepositives": ["Administrative activities"],
                "level": "medium",
                "data": "attack_data.json",
                "source": "WinEventLog:Microsoft-Windows-Sysmon/Operational",
                "sourcetype": "xmlwineventlog"
            }
            st.code(yaml.dump(example_detection, default_flow_style=False), language="yaml")
        
        # Text area for YAML input
        detection_yaml = st.text_area(
            "Enter your Sigma detection rule (YAML format):",
            height=400,
            placeholder="Paste your Sigma detection YAML here...",
            help="Enter a complete Sigma detection rule in YAML format"
        )
        
        # Validate YAML
        detection_data = None
        if detection_yaml:
            try:
                detection_data = yaml.safe_load(detection_yaml)
                st.success("✅ Valid YAML format")
                
                # Display parsed detection info
                if detection_data:
                    st.info(f"**Title:** {detection_data.get('title', 'N/A')}")
                    st.info(f"**Description:** {detection_data.get('description', 'N/A')}")
                    st.info(f"**Level:** {detection_data.get('level', 'N/A')}")
                    
            except yaml.YAMLError as e:
                st.error(f"❌ Invalid YAML: {str(e)}")
                detection_data = None

    with col2:
        st.header("📤 Attack Data")
        
        # File upload for attack data
        uploaded_file = st.file_uploader(
            "Upload attack data file",
            type=['json', 'txt', 'log', 'xml'],
            help="Upload the attack data file to test against your detection"
        )
        
        if uploaded_file:
            st.success(f"✅ File uploaded: {uploaded_file.name}")
            st.info(f"File size: {len(uploaded_file.getvalue())} bytes")
            
            # Show file preview
            with st.expander("👀 Preview file content"):
                try:
                    content = uploaded_file.getvalue().decode('utf-8')
                    # Show first 1000 characters
                    preview = content[:1000]
                    if len(content) > 1000:
                        preview += "\n... (truncated)"
                    st.code(preview)
                except UnicodeDecodeError:
                    st.warning("⚠️ Binary file - cannot preview content")
        
        # Additional parameters
        st.subheader("📋 Data Parameters")
        
        # Auto-populate from detection if available
        default_source = ""
        default_sourcetype = ""
        if detection_data:
            default_source = detection_data.get('source', 'test')
            default_sourcetype = detection_data.get('sourcetype', 'test')
        
        source = st.text_input(
            "Source",
            value=default_source,
            placeholder="WinEventLog:Microsoft-Windows-Sysmon/Operational",
            help="Splunk source field for the data"
        )
        
        sourcetype = st.text_input(
            "Source Type",
            value=default_sourcetype,
            placeholder="xmlwineventlog",
            help="Splunk sourcetype field for the data"
        )

    # Test execution section
    st.header("🚀 Run Detection Test")
    
    # Check if everything is ready
    can_test = (
        detection_data is not None and 
        uploaded_file is not None and 
        host and username and password and
        source and sourcetype
    )
    
    if not can_test:
        missing_items = []
        if not detection_data:
            missing_items.append("Valid Sigma detection")
        if not uploaded_file:
            missing_items.append("Attack data file")
        if not (host and username and password):
            missing_items.append("Splunk connection details")
        if not (source and sourcetype):
            missing_items.append("Data parameters (source/sourcetype)")
            
        st.warning(f"⚠️ Missing: {', '.join(missing_items)}")
    
    # Test button
    if st.button("🔬 Run Detection Test", disabled=not can_test, type="primary"):
        if can_test:
            try:
                with st.spinner("Running detection test..."):
                    # Initialize detection manager if not already done
                    if 'detection_manager' not in st.session_state:
                        detection_manager = DetectionTestingManager(host, username, password)
                        st.session_state.detection_manager = detection_manager
                    else:
                        detection_manager = st.session_state.detection_manager
                    
                    # Configure HEC
                    st.info("🔧 Configuring HTTP Event Collector...")
                    detection_manager.configure_hec()
                    
                    # Save uploaded file to temporary location
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix=f'_{uploaded_file.name}') as tmp_file:
                        tmp_file.write(uploaded_file.getvalue())
                        tmp_file_path = tmp_file.name
                    
                    try:
                        # Send attack data
                        st.info("📤 Sending attack data to Splunk...")
                        detection_manager.send_attack_data(
                            file_path=tmp_file_path,
                            source=source,
                            sourcetype=sourcetype,
                            host=host
                        )
                        st.success("✅ Attack data sent successfully")
                        
                        # Wait for indexing
                        import time
                        st.info("⏳ Waiting for data to be indexed...")
                        time.sleep(3)
                        
                        # Convert detection to Splunk search
                        st.info("🔄 Converting Sigma detection to Splunk search...")
                        splunk_search = detection_manager.sigma_to_splunk_conversion(detection_data)
                        
                        # Show generated search
                        with st.expander("🔍 Generated Splunk Search"):
                            st.code(splunk_search, language="splunk")
                        
                        # Run detection
                        st.info("🚀 Running detection...")
                        result = detection_manager.run_detection(splunk_search)
                        
                        # Display results
                        st.header("📊 Test Results")
                        
                        if result:
                            st.success("🎯 **DETECTION TRIGGERED!**")
                            st.success("✅ Your detection rule successfully identified the attack data")
                            st.balloons()
                        else:
                            st.error("❌ **NO DETECTION**")
                            st.error("🔍 Your detection rule did not trigger on the provided attack data")
                            st.info("💡 **Troubleshooting Tips:**")
                            st.info("• Check if your detection logic matches the attack data format")
                            st.info("• Verify the field names in your detection rule")
                            st.info("• Ensure the attack data contains the expected indicators")
                            st.info("• Try running the generated Splunk search manually")
                        
                        # Additional info
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Detection Title", detection_data.get('title', 'N/A'))
                        with col2:
                            st.metric("Detection Level", detection_data.get('level', 'N/A'))
                        with col3:
                            st.metric("File Size", f"{len(uploaded_file.getvalue())} bytes")
                        
                        # Cleanup
                        if not skip_cleanup:
                            st.info("🧹 Cleaning up attack data...")
                            detection_manager.delete_attack_data()
                            st.success("✅ Attack data cleaned up")
                        else:
                            st.warning("⚠️ Attack data was not cleaned up (as requested)")
                            
                    finally:
                        # Clean up temporary file
                        try:
                            os.unlink(tmp_file_path)
                        except:
                            pass
                            
            except Exception as e:
                st.error(f"❌ Error during testing: {str(e)}")
                st.error("Please check your inputs and try again")
                
                # Try to clean up on error if possible
                if not skip_cleanup:
                    try:
                        if 'detection_manager' in st.session_state:
                            st.session_state.detection_manager.delete_attack_data()
                            st.info("✅ Cleaned up attack data after error")
                    except:
                        pass

    # Help section
    with st.expander("ℹ️ Help & Documentation", expanded=False):
        st.markdown("""
        ### How to use this tool:
        
        1. **Configure Splunk Connection**: Enter your Splunk server details in the sidebar
        2. **Test Connection**: Click "Test Connection" to verify your Splunk settings
        3. **Enter Detection Rule**: Paste your Sigma detection YAML in the left panel
        4. **Upload Attack Data**: Upload a file containing attack data to test against
        5. **Set Parameters**: Configure source and sourcetype for your data
        6. **Run Test**: Click "Run Detection Test" to execute the test
        
        ### Sigma Detection Format:
        Your detection should include standard Sigma fields like:
        - `title`, `description`, `author`, `date`
        - `logsource` with `category` and `product`
        - `detection` with selection criteria and condition
        - `level` (low, medium, high, critical)
        
        ### Attack Data:
        Upload files in formats like JSON, XML, TXT, or LOG that match your detection's expected log source.
        
        ### Environment Variables:
        You can set these environment variables to auto-populate connection details:
        - `SPLUNK_HOST`
        - `SPLUNK_USERNAME` 
        - `SPLUNK_PASSWORD`
        """)


if __name__ == "__main__":
    main()
