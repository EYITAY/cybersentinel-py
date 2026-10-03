# CyberSentinel Py

**A lightweight, explainable Python security analysis toolkit.**

CyberSentinel Py analyzes URLs and text using transparent, rule-based security indicators. It produces a score, threat level, explanation, and recommendation so developers can understand **why** a result was produced.

## Install

```bash
python3 -m pip install cybersentinel-py
```

## Quick Start

Analyze a URL:

```bash
cybersentinel url "http://example.com"
```

Example output:

```text
CyberSentinel Py
----------------
Score: 15
Threat: LOW

Why:
• The URL uses HTTP instead of HTTPS. (+15)

Recommendation:
Use HTTPS and verify the destination before entering sensitive information.
```

Analyze text:

```bash
cybersentinel text "URGENT: Verify your account immediately."
```

## What It Analyzes

### URLs

CyberSentinel Py 0.1.0 includes indicators for:

* HTTP instead of HTTPS
* IP-address hosts
* Embedded credentials
* Percent-encoded characters
* Unusually long URLs
* Non-standard ports
* Unexpected URL schemes

### Text

The text analyzer currently looks for security-related signals such as:

* Urgent language
* Credential-related requests
* Suspicious link instructions

## How It Works

CyberSentinel Py follows a simple analysis pipeline:

```text
Input
  ↓
Analyzer
  ↓
Security Indicators
  ↓
Score
  ↓
Threat Level
  ↓
Explanation
  ↓
Recommendation
```

The system is designed to make its reasoning visible rather than returning only a risk score.

## Python Usage

CyberSentinel Py can also be used from Python code:

```python
from cybersentinel.analyzers.url import URLAnalyzer

analyzer = URLAnalyzer()
result = analyzer.analyze("http://example.com")

print(result.score)
print(result.threat_level)
```

This allows CyberSentinel Py to be used as a component inside larger Python applications.

## Testing

Clone the repository:

```bash
git clone https://github.com/EYITAY/cybersentinel-py.git
cd cybersentinel-py
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project:

```bash
python3 -m pip install -e .
```

Install the test dependencies:

```bash
python3 -m pip install pytest
```

Run the tests:

```bash
pytest
```

CyberSentinel Py 0.1.0 currently has **31 automated tests**.

## Design Philosophy

CyberSentinel Py is built around four principles:

**Explainable**
Security results should show the signals that produced them.

**Modular**
Analyzers, models, scoring, explanation, and CLI functionality are separated.

**Testable**
Security rules should be backed by automated tests.

**Practical**
The package is intended to be useful inside real Python development workflows.

## Important Limitation

CyberSentinel Py uses rule-based heuristics.

A detected indicator is **not proof that an input is malicious**, and the absence of an indicator is not proof that an input is safe.

Results should be treated as security signals that can support further investigation.

## Project Links

**GitHub**
https://github.com/EYITAY/cybersentinel-py

**PyPI**
https://pypi.org/project/cybersentinel-py/

**CyberSentinel**
https://cybersentinelai-eight.vercel.app/

## Documentation

Tutorials and developer documentation are being developed to help users:

* install and use CyberSentinel Py;
* understand its architecture;
* create security rules;
* write tests;
* extend the package; and
* build applications with CyberSentinel Py.

## Contributing

CyberSentinel Py is designed to grow through experimentation, testing, and developer contributions.

See the GitHub repository for the latest development information.

## License

CyberSentinel Py is released under the **Apache License 2.0**.

See [LICENSE](LICENSE) for the full license text.
