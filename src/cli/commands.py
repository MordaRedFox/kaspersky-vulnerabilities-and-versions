"""
Обработчики подкоманд.
Каждый обработчик имеет сигнатуру (con, args) -> int (exit code)
и не зависит от argparse: читает только нужные поля из args.
Это позволяет использовать обработчики в любом интерфейсе
(CLI, REPL, программный вызов)
Exit codes:
  0 - успех
  1 - runtime (продукт не найден, нет БД)
  2 - bad input (невалидная версия, неоднозначный продукт)
"""

import json
import sqlite3
import sys
from dataclasses import asdict
from src import db, logic
from src.versions import parse_version


def cmd_safe_versions(con: sqlite3.Connection, args) -> int:
    """
    Обработать safe-versions: список версий продукта без уязвимостей
    Args:
        con: соединение с БД (read-only)
        args: namespace с полями product, vendor, latest, json
    Returns:
        Exit code: 0 / 1 / 2
    """
    try:
        result = logic.safe_versions(con, args.product, args.vendor)
    except logic.ProductNotFoundError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 1
    except logic.AmbiguousProductError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 2
    versions = result.safe_versions
    if args.latest:
        versions = versions[-1:] if versions else []
    if args.json:
        payload = {
            'vendor': result.product.vendor,
            'product': result.product.product,
            'safe_versions': versions
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        header = f'{result.product.product} ({result.product.vendor})'
        if not versions:
            print(f"{header}: безопасных версий в фиде нет.")
        else:
            print(f"{header}: безопасные версии ({len(versions)}):")
            for v in versions:
                print(f"  {v}")
    return 0


def cmd_vulns(con: sqlite3.Connection, args) -> int:
    """
    Обработать vulns: уязвимости, актуальные для конкретной версии
    Args:
        con: соединение с БД (read-only)
        args: namespace с полями product, version, vendor, json
    Returns:
        Exit code: 0 / 1 / 2
    """
    try:
        parse_version(args.version)
    except ValueError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 2
    try:
        result = logic.vulns_for(con, args.product, args.version, args.vendor)
    except logic.ProductNotFoundError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 1
    except logic.AmbiguousProductError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 2
    if args.json:
        payload = {
            'vendor': result.product.vendor,
            'product': result.product.product,
            'version': result.version,
            'vulns': [asdict(v) for v in result.vulns]
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        header = (
            f'{result.product.product} '
            f'({result.product.vendor}) {result.version}'
        )
        if not result.vulns:
            print(f"{header}: уязвимостей не найдено.")
        else:
            print(f"{header} — найдено уязвимостей: {len(result.vulns)}.")
            print()
            for v in result.vulns:
                print(f"  {v.kla_id}  ({v.publish_date or 'дата неизвестна'})")
                if v.description:
                    print(f"    {v.description}")
                print(f"    фиксы: {', '.join(v.fixes)}")
                if len(v.ranges) > 1:
                    branches = ", ".join(f"[{s}, {f})" for s, f in v.ranges)
                    print(f"    ветки: {branches}")
                print()
    return 0


def cmd_list_products(con: sqlite3.Connection, args) -> int:
    """
    Обработать list-products: список продуктов в БД
    Args:
        con: cоединение с БД (read-only)
        args: namespace с полем json
    Returns:
        Exit code (всегда 0)
    """
    rows = db.list_all_products(con)
    if args.json:
        payload = [
            {'vendor': r['vendor'], 'product': r['product']}
            for r in rows
        ]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        if not rows:
            print("В БД нет продуктов.")
        else:
            width = max(len(r['vendor']) for r in rows)
            for r in rows:
                print(f"{r['vendor']:<{width}}  {r['product']}")
    return 0


# Реестр подкоманд
# Добавить подкоманду = обработчик + запись сюда + parsers.add_subcommands
COMMANDS = {
    'safe-versions': cmd_safe_versions,
    'vulns': cmd_vulns,
    'list-products': cmd_list_products
}
