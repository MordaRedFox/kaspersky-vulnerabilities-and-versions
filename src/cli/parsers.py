"""
Парсеры argparse для обычного запуска (с --db) и REPL (без --db)
"""

import argparse
from pathlib import Path
from src import db


def add_subcommands(sub: argparse._SubParsersAction) -> None:
    """
    Зарегистрировать подкоманды в subparsers.
    Единственное место, где описывается набор подкоманд. Используется
    и one-shot-парсером, и REPL-парсером, чтобы они не расходились
    Args:
        sub: результат parser.add_subparsers(...)
    """
    safe = sub.add_parser(
        'safe-versions', help='Версии продукта без уязвимостей')
    safe.add_argument('product', help='Точное имя продукта')
    safe.add_argument('--vendor', default=None, help='Уточнить вендора')
    safe.add_argument(
        '--latest',
        action='store_true',
        help='Показать только максимальную безопасную версию'
    )
    safe.add_argument('--json', action='store_true', help='Машинный вывод')
    vulns = sub.add_parser('vulns', help='Уязвимости для конкретной версии')
    vulns.add_argument('product', help='Точное имя продукта')
    vulns.add_argument('version', help='Версия, например 15.3.1')
    vulns.add_argument('--vendor', default=None, help='Уточнить вендора')
    vulns.add_argument('--json', action='store_true', help='Машинный вывод')
    lp = sub.add_parser('list-products', help='Список продуктов в БД')
    lp.add_argument('--json', action='store_true', help='Машинный вывод')


def build_parser() -> argparse.ArgumentParser:
    """
    Собрать парсер one-shot-режима (с флагом --db)
    Returns:
        ArgumentParser с --db и подкомандами
    """
    parser = argparse.ArgumentParser(
        prog='vulncli',
        description='Уязвимости и безопасные версии продуктов.'
    )
    parser.add_argument(
        '--db',
        type=Path,
        default=db.DEFAULT_DB_PATH,
        help=f'Путь к SQLite (по умолчанию {db.DEFAULT_DB_PATH})'
    )
    sub = parser.add_subparsers(dest='cmd', required=True)
    add_subcommands(sub)
    return parser


def build_repl_parser() -> argparse.ArgumentParser:
    """
    Собрать парсер для REPL - те же подкоманды, но без --db
    В REPL соединение уже открыто, --db там не имеет смысла
    Returns:
        ArgumentParser с подкомандами, без --db
    """
    parser = argparse.ArgumentParser(prog='', add_help=True)
    sub = parser.add_subparsers(dest='cmd', required=True)
    add_subcommands(sub)
    return parser
