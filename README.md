CyberSentinel Py

CyberSentinel Py is a lightweight Python security analysis toolkit for detecting basic security indicators in URLs and text.



The project is designed around simple, explainable security rules that produce a standardized threat result with a score, threat level, detected indicators, explanation, and recommendation.

It detects basic security indicators, calculates a threat score, assigns a threat level, and explains the detected signals.

## Example

```text
cybersentinel url "http://example.com"
```

```text
CyberSentinel Py
----------------
Score: 15
Threat: LOW
```

## Installation

```bash
git clone https://github.com/EYITAY/cybersentinel-py.git
cd cybersentinel-py
python3 -m pip install -e .
```

## Testing

```bash
pytest
```

## Status

Active development.
