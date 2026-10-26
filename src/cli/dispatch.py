"""
Роутинг подкоманд: по args.cmd вызывает нужный обработчик
"""

import sqlite3
import sys
from src.cli.commands import COMMANDS


def dispatch(con: sqlite3.Connection, args) -> int:
    """
    Найти обработчик по args.cmd и вызвать его
    Args:
        con: соединение с БД (read-only)
        args: namespace с полем cmd и параметрами подкоманды
    Returns:
        Exit code, который вернул обработчик. 2, если подкоманда неизвестна
    """
    handler = COMMANDS.get(args.cmd)
    if handler is None:
        print(f"Неизвестная команда: {args.cmd}", file=sys.stderr)
        return 2
    return handler(con, args)
