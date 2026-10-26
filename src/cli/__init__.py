"""
Пакет CLI. Реэкспорт публичного API для обратной совместимости:
    from src.cli import main, entrypoint, run_repl
"""

from src.cli.app import entrypoint, main
from src.cli.commands import (
    COMMANDS, cmd_list_products, cmd_safe_versions, cmd_vulns)
from src.cli.dispatch import dispatch
from src.cli.parsers import add_subcommands, build_parser, build_repl_parser
from src.cli.repl import REPL_HELP, run_repl

__all__ = [
    'main',
    'entrypoint',
    'run_repl',
    'REPL_HELP',
    'build_parser',
    'build_repl_parser',
    'add_subcommands',
    'dispatch',
    'COMMANDS',
    'cmd_safe_versions',
    'cmd_vulns',
    'cmd_list_products'
]
