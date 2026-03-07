"""CLI for prompt-security-utils."""

import argparse
import json
import sys
from pathlib import Path

from prompt_security.config import generate_markers, load_config
from prompt_security.wrapping import wrap_external_data, read_and_wrap_file


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="prompt-security-utils",
        description=(
            "Wrap external content with security markers for safe LLM consumption.\n"
            "\n"
            "Reads content from FILE or stdin, wraps it with security markers, runs the\n"
            "full prompt injection detection pipeline (regex + semantic similarity), and\n"
            "outputs the wrapped JSON to stdout.\n"
            "\n"
            "Output is a JSON object with these fields:\n"
            '  trust_level            Always "external"\n'
            '  source_type            Always "external"\n'
            "  source_id              From --source-id, or auto-generated\n"
            "  warning                Human-readable data boundary warning\n"
            "  content_start_marker   Random session marker (start)\n"
            "  data                   The original content\n"
            "  content_end_marker     Random session marker (end)\n"
            "  security_warnings      (only if suspicious patterns detected)"
        ),
        epilog=(
            "Examples:\n"
            "  prompt-security-utils report.txt\n"
            "  prompt-security-utils report.txt --source-id attachment:456\n"
            "  jq '.data' stored.json | prompt-security-utils\n"
            "  jq '.data' stored.json | prompt-security-utils --source-id query:ticket:789"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file", nargs="?", default=None,
        help="File to wrap (reads from stdin if omitted or if stdin is piped)",
    )
    parser.add_argument(
        "--source-id", default=None,
        help="Source identifier (defaults to file:<filename> or 'stdin')",
    )

    args = parser.parse_args()
    start, end = generate_markers()
    config = load_config()

    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)

        source_id = args.source_id or f"file:{path.name}"
        result = read_and_wrap_file(args.file, "external", source_id, start, end, config)

        if result is None:
            print("Error: file is empty or could not be read", file=sys.stderr)
            sys.exit(1)
    else:
        if sys.stdin.isatty():
            parser.print_help(sys.stderr)
            sys.exit(1)

        content = sys.stdin.read()
        if not content:
            print("Error: no data on stdin", file=sys.stderr)
            sys.exit(1)

        source_id = args.source_id or "stdin"
        result = wrap_external_data(content, "external", source_id, start, end, config)

        if result is None:
            print("Error: empty content", file=sys.stderr)
            sys.exit(1)

    json.dump(result, sys.stdout, indent=2, default=str)
    print()


if __name__ == "__main__":
    main()
