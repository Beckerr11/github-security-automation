#!/usr/bin/env python3
import argparse

def main() -> None:
    parser = argparse.ArgumentParser(description='GitHub security automation scaffold')
    parser.add_argument('--owner', default='Beckerr11', help='GitHub owner')
    parser.add_argument('--output', default='security-report.md', help='Output file')
    args = parser.parse_args()

    report = f\"# Security report\\n\\nOwner: {args.owner}\\n\\nScaffold inicial pronto.\"\n
    with open(args.output, 'w', encoding='utf-8') as fp:
        fp.write(report)

    print(f'Relatorio gerado em {args.output}')

if __name__ == '__main__':
    main()