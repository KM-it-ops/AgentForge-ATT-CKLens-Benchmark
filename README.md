# ATT&CKLens

**ATT&CKLens** is a defensive cybersecurity helper that maps sample security observations to MITRE ATT&CK tactics and techniques. It is designed for educational use in controlled lab environments to help analysts understand potential adversary behavior and generate defensive ideas.

## Features

- **Input Processing**: Accepts various types of security observations including:
  - System log snippets (authentication logs, process creation logs, etc.)
  - Alert text from SIEM products
  - Scan summaries (Nmap output, vulnerability scans)
  - Packet-analysis notes
  - Narrative incident descriptions

- **ATT&CK Mapping**: Maps observations to MITRE ATT&CK:
  - Tactics (Initial Access, Execution, Persistence, etc.)
  - Techniques with IDs (T1059.001, T1110, etc.)
  - Confidence levels (high, medium, low)

- **Defensive Guidance**: Provides:
  - Detection ideas (SIEM/Splunk query suggestions)
  - Network investigation guidance
  - Remediation recommendations
  - Analyst questions for further investigation

- **Safety Features**:
  - Prompt injection resistance
  - No offensive guidance
  - Honest limitations reporting
  - Educational purpose only

## Quick Start

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/KM-it-ops/agentforge-attacklens-benchmark.git
   cd agentforge-attacklens-benchmark
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python app.py
   ```

4. Open your browser to the URL displayed in the console (typically `http://localhost:7860`)

### Usage

1. Enter a security observation in the text box
2. Click "Analyze" to get the ATT&CK mapping
3. Review the results which include:
   - Summary of the observation
   - Mapped MITRE ATT&CK tactic and technique
   - Evidence fragments from the input
   - Confidence level
   - Detection ideas
   - Network investigation guidance
   - Remediation recommendations
   - Analyst questions

## Examples

### Example 1: Failed SSH Login
**Input:**
```
Failed SSH login from 10.0.0.5 for user root
```

**Output:**
- **Tactic:** Initial Access
- **Technique ID:** T1110 (Brute Force)
- **Confidence:** Medium/High
- **Evidence:** ["Failed SSH login", "SSH", "login"]
- **Detection Idea:** Search for repeated failed login attempts from the same IP
- **Remediation:** Implement account lockout, enforce strong passwords, enable MFA

### Example 2: DNS Requests
**Input:**
```
Repeated DNS requests to suspicious-domain.com every minute from 192.168.1.42
```

**Output:**
- **Tactic:** Command and Control
- **Technique ID:** T1071.004 (DNS)
- **Confidence:** Medium/High
- **Network Investigation:** Inspect DNS traffic for suspicious queries
- **Remediation:** Monitor DNS queries, block known malicious domains

### Example 3: Ambiguous Input
**Input:**
```
User reported that the system seemed slow yesterday.
```

**Output:**
- **Tactic:** None
- **Technique ID:** None
- **Confidence:** Low
- **Why Not:** Insufficient evidence to map to a specific MITRE ATT&CK tactic or technique

## Project Structure

```
.
├── app.py                      # Gradio entry point
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── SECURITY.md                 # Safety rules and ethical use
├── STATE.md                    # Development state tracking
├── src/
│   └── core.py                # Core analysis logic
├── tests/
│   └── test_core.py           # Unit tests
└── .gitignore                 # Git ignore rules
```

## Architecture

The application consists of two main components:

1. **Core Logic (`src/core.py`)**: Contains the pattern matching engine that maps security observations to MITRE ATT&CK tactics and techniques. Uses embedded MITRE ATT&CK technique data with regex patterns for matching.

2. **User Interface (`app.py`)**: Gradio-based web interface that provides an easy-to-use form for entering observations and displaying results.

### Data Flow

1. User enters security observation
2. Input is passed to `analyse_input()` function
3. Function checks for prompt injection attempts
4. Pattern matching identifies relevant MITRE ATT&CK techniques
5. Results are formatted and returned to the user

## Testing

Run the unit tests to verify functionality:

```bash
pytest tests/test_core.py -v
```

The tests cover:
- Basic mapping functionality
- Handling of ambiguous input
- Prompt injection resistance
- Network investigation field
- Edge cases and error handling
- Output structure validation

## Limitations

- **Static Data**: Uses embedded MITRE ATT&CK technique data; does not fetch live updates
- **Pattern Matching**: Relies on regex pattern matching which may not catch all variations
- **No LLM**: Does not use large language models; all processing is deterministic
- **Single Input**: Processes one observation at a time (no batch processing)
- **Educational Use**: Intended for lab environments only, not production use

## Security Considerations

See [SECURITY.md](SECURITY.md) for detailed safety rules and ethical use guidelines.

### Key Safety Features

- **No Offensive Guidance**: Never provides instructions for exploiting systems
- **Prompt Injection Resistance**: Detects and handles prompt injection attempts
- **Honest Limitations**: Clearly states when mapping is uncertain
- **Educational Focus**: All outputs are framed for defensive purposes

## Deployment

### Hugging Face Spaces

This application is designed to run on Hugging Face Spaces:

1. Create a new Space
2. Select "Gradio" as the SDK
3. Upload the repository contents
4. The Space will automatically launch the application

### Local Deployment

For local deployment, simply run:

```bash
python app.py
```

The application will start a local web server accessible at `http://localhost:7860`

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass
2. New features follow the existing architecture
3. Safety rules are maintained
4. Documentation is updated

## License

This project is provided for educational purposes. See the repository license for details.

## Acknowledgments

- MITRE ATT&CK framework for the comprehensive adversary behavior taxonomy
- Gradio for the easy-to-use web interface
- The cybersecurity community for continuous learning and improvement
