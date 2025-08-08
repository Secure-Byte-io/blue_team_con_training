# Sigma Detection Testing with Streamlit

A user-friendly web interface for testing Sigma detection rules against attack data using Splunk.

## Features

- 🔍 **Interactive UI**: Easy-to-use web interface for detection testing
- 📝 **Sigma Rule Input**: Paste and validate Sigma detection rules in YAML format
- 📤 **File Upload**: Upload attack data files for testing
- 🔌 **Splunk Integration**: Direct connection to Splunk for real-time testing
- 📊 **Visual Results**: Clear feedback on detection success/failure
- 🧹 **Automatic Cleanup**: Optional cleanup of test data
- ⚙️ **Configuration**: Flexible Splunk connection settings

## Requirements

- Python 3.7+
- Splunk instance with appropriate permissions
- Required Python packages (see requirements.txt)

## Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment variables (optional):**
   ```bash
   export SPLUNK_HOST="your-splunk-host"
   export SPLUNK_USERNAME="your-username" 
   export SPLUNK_PASSWORD="your-password"
   ```

## Usage

1. **Start the Streamlit app:**
   ```bash
   streamlit run streamlit.py
   ```

2. **Open your browser** and navigate to `http://localhost:8501`

3. **Configure Splunk connection** in the sidebar:
   - Enter your Splunk host, username, and password
   - Click "Test Connection" to verify settings

4. **Enter your Sigma detection rule** in YAML format in the left panel

5. **Upload attack data file** in the right panel (JSON, XML, TXT, or LOG format)

6. **Configure data parameters**:
   - Set appropriate source and sourcetype values
   - These will auto-populate from your detection rule if specified

7. **Run the test** by clicking "Run Detection Test"

## Example Sigma Detection

```yaml
title: Example Process Execution Detection
id: 12345678-1234-1234-1234-123456789abc
status: test
description: Detects suspicious process execution
author: Security Team
date: 2024-01-01
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
    CommandLine|contains: 'whoami'
  condition: selection
falsepositives:
  - Administrative activities
level: medium
source: WinEventLog:Microsoft-Windows-Sysmon/Operational
sourcetype: xmlwineventlog
```

## How It Works

1. **Detection Input**: The app validates your Sigma YAML and shows parsed information
2. **Data Upload**: Attack data files are temporarily stored and uploaded to Splunk via HEC
3. **Conversion**: Sigma rules are converted to Splunk searches using the pysigma library
4. **Testing**: The generated search is executed against the uploaded data
5. **Results**: Visual feedback shows whether the detection triggered
6. **Cleanup**: Test data is automatically removed (unless disabled)

## Troubleshooting

### Connection Issues
- Verify Splunk host, username, and password
- Ensure Splunk is accessible from your network
- Check if HTTP Event Collector is enabled in Splunk

### Detection Not Triggering
- Verify field names match between detection and attack data
- Check if attack data format matches expected log source
- Review the generated Splunk search in the expandable section
- Try running the search manually in Splunk

### File Upload Issues
- Ensure file format is supported (JSON, XML, TXT, LOG)
- Check file encoding (UTF-8 recommended)
- Verify file size is reasonable

## Advanced Features

### Environment Variables
Set these to auto-populate connection details:
- `SPLUNK_HOST`: Splunk server hostname/IP
- `SPLUNK_USERNAME`: Splunk username
- `SPLUNK_PASSWORD`: Splunk password

### Skip Cleanup
Use the "Skip data cleanup" option to preserve test data in Splunk for manual analysis.

### Debug Mode
Check the generated Splunk search to understand how your Sigma rule was converted.

## Integration with Existing Tools

This Streamlit app uses the same core functionality as:
- `detection_testing_manager.py`: Splunk connection and HEC management
- `test_detections.py`: Batch testing logic

You can also use the command-line tools for automated testing:
```bash
python test_detections.py /path/to/detections/
```

## Security Considerations

- Store credentials securely using environment variables
- Use dedicated Splunk accounts with minimal required permissions
- Clean up test data regularly if using skip cleanup option
- Review uploaded files for sensitive information

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review Splunk logs for detailed error messages
3. Verify your Sigma detection syntax using online validators
4. Test with simple, known-good detection rules first
