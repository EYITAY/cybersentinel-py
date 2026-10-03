import sys

from cybersentinel.analyzers.text import TextAnalyzer
from cybersentinel.analyzers.url import URLAnalyzer
from cybersentinel.explain import format_result


def main():
    """Run the CyberSentinel Py command-line interface."""

    if len(sys.argv) < 3:
        print("Usage:")
        print('  cybersentinel url "<URL>"')
        print('  cybersentinel text "<TEXT>"')
        return

    input_type = sys.argv[1].lower()
    value = sys.argv[2]

    if input_type == "url":
        analyzer = URLAnalyzer()
    elif input_type == "text":
        analyzer = TextAnalyzer()
    else:
        print("Error: Input type must be 'url' or 'text'.")
        return

    result = analyzer.analyze(value)

    print(format_result(result))