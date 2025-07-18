# GitHub Actions Workflows for Detection Rules

This directory contains GitHub Actions workflows to automatically validate and test your Sigma detection rules.

## Workflows

### 1. Validate Detection Rules (`validate-detections.yml`)

**Purpose**: Validates all YAML detection files in the `detections/` folder against the Sigma schema.

**Triggers**:
- Push to `main` or `develop` branches (when detection files or validation scripts change)
- Pull requests to `main` or `develop` branches
- Manual trigger via GitHub UI

**What it does**:
- Checks out the repository
- Sets up Python 3.11
- Installs required dependencies (`PyYAML`, `jsonschema`)
- Runs `validate.py` on the `detections/` folder using the Sigma schema
- Uploads validation results as artifacts

### 2. Test Detection Rules (`test-detections.yml`)

**Purpose**: Tests detection rules against a live Splunk instance to verify they work correctly.

**Triggers**:
- Automatically runs when "Validate Detection Rules" workflow completes successfully
- Manual trigger via GitHub UI (with option to skip validation requirement)

**What it does**:
- Only runs if validation passed (or manually triggered with skip option)
- Sets up Python 3.11 and installs Splunk-related dependencies
- Connects to Splunk using provided credentials
- Runs each detection rule and verifies it triggers correctly
- Uploads test results as artifacts
- Comments on PRs if tests fail

## Setup Requirements

### 1. Repository Secrets

To use the testing workflow, you must configure the following secrets in your GitHub repository:

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Add these repository secrets:

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `SPLUNK_HOST` | Your Splunk server hostname/IP | `192.168.1.100` or `splunk.company.com` |
| `SPLUNK_USERNAME` | Splunk username with search permissions | `admin` |
| `SPLUNK_PASSWORD` | Splunk user password | `your_password` |

### 2. Splunk Requirements

Your Splunk instance must have:
- HTTP Event Collector (HEC) enabled
- User account with permissions to:
  - Send data via HEC
  - Run searches
  - Access relevant indexes

### 3. Detection File Format

Detection files in the `detections/` folder should follow the Sigma format and optionally include:

```yaml
title: "Your Detection Rule"
# ... other Sigma fields ...

# Optional: Test data file (relative to detection file)
data: "test_data.json"
source: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
sourcetype: "xmlwineventlog"
```

## Usage

### Automatic Execution

1. **Push changes** to detection files in the `detections/` folder
2. **Validation workflow** runs automatically
3. **If validation passes**, testing workflow runs automatically
4. **Check results** in the Actions tab

### Manual Execution

1. Go to **Actions** tab in GitHub
2. Select the workflow you want to run
3. Click **Run workflow**
4. For testing workflow, you can optionally skip validation requirement

### Viewing Results

1. **Actions tab**: See workflow run status and logs
2. **Artifacts**: Download detailed results (available for 30 days)
3. **PR comments**: Automatic comments on failed tests in pull requests

## Workflow Outputs

### Validation Results
- Console output showing which files passed/failed validation
- Exit code 0 for success, 1 for failure
- Detailed error messages for invalid files

### Test Results
- Summary of detection tests (successful/failed/total)
- Success rate percentage
- Detailed logs for each detection test
- Information about test data sent to Splunk

## Troubleshooting

### Validation Fails
- Check YAML syntax in detection files
- Ensure all required Sigma fields are present
- Verify schema compliance

### Testing Fails
- Verify Splunk secrets are correctly configured
- Check Splunk connectivity and permissions
- Ensure HEC is enabled and accessible
- Review test data format and content

### Missing Dependencies
- Workflows automatically install required Python packages
- Check if specific versions are needed in requirements files

## File Structure

```
.github/workflows/
├── README.md                    # This file
├── validate-detections.yml      # Validation workflow
└── test-detections.yml         # Testing workflow

detections/                      # Your detection rules
├── detection1.yml
├── detection2.yml
└── ...

solutions/lab7/
└── validate.py                  # Validation script

solutions/lab9/
├── test_detections.py          # Testing script
└── detection_testing_manager.py # Testing helper

labs/lab7/
└── sigma.schema.json           # Sigma schema for validation
```

## Security Considerations

- Splunk credentials are stored as encrypted GitHub secrets
- Workflows run in isolated environments
- Test data is automatically cleaned up after testing
- Consider using dedicated test Splunk instance for CI/CD 