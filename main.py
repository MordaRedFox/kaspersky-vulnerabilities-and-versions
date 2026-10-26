"""
Точка входа CLI

Без аргументов запускает интерактивный режим (REPL) CLI:
    python main.py
С аргументами запускается one-shot режим CLI:
    python main.py safe-versions "VLC media player"
    python main.py vulns "PostgreSQL" "15.3.1"
    python main.py list-products
    python main.py --help

Exit code: 0 - успех, 1 - runtime-ошибка, 2 - ошибка ввода
"""

import sys
from src.cli import entrypoint


if __name__ == '__main__':
    sys.exit(entrypoint())
