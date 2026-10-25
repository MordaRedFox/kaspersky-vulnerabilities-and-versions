"""
Загрузка versions.json и vulnerabilities.json в SQLite
"""

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
FEED = ROOT / 'feed'
DB_PATH = ROOT / 'data' / 'vulndb.sqlite'
SCHEMA = ROOT / 'schema.sql'


def get_or_create_vendor(cur: sqlite3.Cursor, name: str) -> int:
    """
    Найти производителя по имени или создать новую запись
    Args:
        cur: курсор SQLite-соединения, в рамках которого выполняются запросы
        name: имя производителя (например, "PostgreSQL")
    Returns:
        Первичный ключ записи в таблице vendors
        (существующей или только что созданной)
    """
    cur.execute("INSERT OR IGNORE INTO vendors(name) VALUES (?)", (name,))
    cur.execute("SELECT id FROM vendors WHERE name = ?", (name,))
    return cur.fetchone()[0]


def get_or_create_product(cur: sqlite3.Cursor, vendor_id: int,
                          name: str) -> int:
    """
    Найти продукт по паре (vendor_id, name) или создать новую запись
    Args:
        cur: курсор SQLite-соединения, в рамках которого выполняются запросы
        vendor_id: первичный ключ производителя из таблицы vendors
        name: имя продукта (например, "PostgreSQL")
    Returns:
        Первичный ключ записи в таблице products
        (существующей или только что созданной)
    """
    cur.execute(
        "INSERT OR IGNORE INTO products(vendor_id, name) VALUES (?, ?)",
        (vendor_id, name),
    )
    cur.execute(
        "SELECT id FROM products WHERE vendor_id = ? AND name = ?",
        (vendor_id, name),
    )
    return cur.fetchone()[0]


def load() -> None:
    """
    Пересоздать БД и загрузить в нее оба фида
    Удаляет существующий файл БД, применяет schema.sql, затем последовательно
    читает feed/versions.json и feed/vulnerabilities.json и вставляет строки.
    Дубли, отсеченные UNIQUE-ограничениями, учитываются в статистике и не
    считаются ошибкой. По завершении печатает сводку: сколько строк загружено,
    сколько отброшено дубликатов, итоговые размеры таблиц и путь к файлу БД
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists():
        DB_PATH.unlink()
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA.read_text(encoding='utf-8'))
    cur = con.cursor()
    versions = json.loads(
        (FEED / 'versions.json').read_text(encoding='utf-8'))
    vulns = json.loads(
        (FEED / 'vulnerabilities.json').read_text(encoding='utf-8'))
    stats = {'ver_ok': 0, 'ver_dup': 0, 'vul_ok': 0, 'vul_dup': 0}
    for row in versions:
        vid = get_or_create_vendor(cur, row['vendor'])
        pid = get_or_create_product(cur, vid, row['product'])
        try:
            cur.execute(
                "INSERT INTO versions(product_id, version) VALUES (?, ?)",
                (pid, row["version"]),
            )
            stats['ver_ok'] += 1
        except sqlite3.IntegrityError:
            stats['ver_dup'] += 1
    for row in vulns:
        vid = get_or_create_vendor(cur, row['vendor'])
        pid = get_or_create_product(cur, vid, row['product'])
        try:
            cur.execute(
                "INSERT INTO vulnerabilities("
                "  product_id, kla_id, description, publish_date,"
                "  start_vuln_version, fixed_version"
                ") VALUES (?, ?, ?, ?, ?, ?)",
                (
                    pid,
                    row["KLA_id"],
                    row.get("description"),
                    row.get("publish_date"),
                    row["start_vuln_version"],
                    row["fixed_version"],
                ),
            )
            stats['vul_ok'] += 1
        except sqlite3.IntegrityError:
            stats['vul_dup'] += 1
    con.commit()

    def scalar(q: str, *p: Any) -> Any:
        """
        Выполнить SQL-запрос и вернуть первый столбец первой строки результата.
        Вспомогательная функция для подсчета строк в сводке
        Args:
            q: SQL-запрос с плейсхолдерами (?) для параметров
            *p: позиционные параметры для подстановки в запрос
        Returns:
            Значение первого столбца первой строки результата запроса
        """
        cur.execute(q, p)
        return cur.fetchone()[0]

    print("Загрузка завершена.")
    print(f"  versions:        ok={stats['ver_ok']:>4}  dup={stats['ver_dup']}")
    print(f"  vulnerabilities: ok={stats['vul_ok']:>4}  dup={stats['vul_dup']}")
    print("Итог в БД:")
    print(f"  vendors:         {scalar('SELECT COUNT(*) FROM vendors')}")
    print(f"  products:        {scalar('SELECT COUNT(*) FROM products')}")
    print(f"  versions:        {scalar('SELECT COUNT(*) FROM versions')}")
    print(f"  vulnerabilities: {scalar('SELECT COUNT(*) FROM vulnerabilities')}")
    print(f"  distinct KLA:    {scalar('SELECT COUNT(DISTINCT kla_id) FROM vulnerabilities')}")
    print(f"  DB: {DB_PATH}")
    con.close()


if __name__ == '__main__':
    try:
        load()
    except FileNotFoundError as e:
        sys.exit(f"Не найден файл: {e.filename}. Положите фиды в ./feed/")
