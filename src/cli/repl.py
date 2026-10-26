"""
Интерактивный цикл (REPL)
"""

import shlex
import sqlite3
import sys
from typing import Callable
from src.cli.dispatch import dispatch
from src.cli.parsers import build_repl_parser


REPL_HELP = """\
Интерактивный режим консольного приложения. Доступные команды:

  safe-versions <product> [--vendor V] [--latest] [--json]
  vulns <product> <version> [--vendor V] [--json]
  list-products [--json]

  help, ?        — эта справка
  exit, quit, q  — выход
  Ctrl+D, Ctrl+C — выход
"""


def run_repl(con: sqlite3.Connection,
             read_line: Callable[[str], str] | None = None,) -> None:
    """
    Запустить интерактивный цикл
    Args:
        con: открытое соединение с БД. Не закрывается здесь -
            закрытие ответственности вызывающего
        read_line: функция чтения строки, read_line(prompt) -> str
    """
    if read_line is None:
        read_line = input
    print("Запуск в интерактивном режиме. 'help' — справка, 'exit' — выход.")
    parser = build_repl_parser()
    while True:
        try:
            line = read_line('vulncli> ').strip()
        except (EOFError, KeyboardInterrupt, StopIteration):
            print()
            break
        if not line:
            continue
        if line.lower() in {'exit', 'quit', 'q'}:
            break
        if line.lower() in {'help', '?'}:
            print(REPL_HELP)
            continue
        try:
            argv = shlex.split(line)
        except ValueError as e:
            print(f"Ошибка разбора команды: {e}", file=sys.stderr)
            continue
        try:
            args = parser.parse_args(argv)
        except SystemExit:
            continue
        try:
            dispatch(con, args)
        except Exception as e:
            print(f"Ошибка: {e}", file=sys.stderr)
