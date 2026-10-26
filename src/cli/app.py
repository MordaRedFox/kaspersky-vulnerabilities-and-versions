"""
Точки входа: one-shot main() и маршрутизатор entrypoint()
"""

import sys
from src import db
from src.cli.dispatch import dispatch
from src.cli.parsers import build_parser
from src.cli.repl import run_repl


def main(argv: list[str] | None = None) -> int:
    """
    One-shot entrypoint: выполнить одну команду и вернуться.
    Без аргументов печатает справку в stderr и возвращает 2.
    REPL запускается через entrypoint(), а не через main()
    Args:
        argv: аргументы без имени программы. None - sys.argv[1:]
    Returns:
        Exit code: 0 успех, 1 runtime, 2 bad input
    """
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        build_parser().print_help(sys.stderr)
        return 2
    args = build_parser().parse_args(argv)
    try:
        con = db.open_db(args.db, readonly=True)
    except FileNotFoundError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 1
    try:
        return dispatch(con, args)
    finally:
        con.close()


def entrypoint(argv: list[str] | None = None) -> int:
    """
    Полный entrypoint: без аргументов - REPL, с аргументами - one-shot
    Args:
        argv: аргументы без имени программы. None - sys.argv[1:]
    Returns:
        Exit code
    """
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return _run_repl_entry()
    return main(argv)


def _run_repl_entry() -> int:
    """
    Открыть БД и запустить REPL
    Returns:
        Exit code: 0 успех, 1 нет БД
    """
    try:
        con = db.open_db(readonly=True)
    except FileNotFoundError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 1
    try:
        run_repl(con)
    finally:
        con.close()
    return 0
