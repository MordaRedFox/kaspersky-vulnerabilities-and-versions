"""
Тонкий слой доступа к SQLite: открытие соединения и простые выборки.
Никакой бизнес-логики - только "дай строки по такому-то запросу"
"""

import sqlite3
from pathlib import Path


DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / 'data' / 'vulndb.sqlite'


def open_db(path: Path | str = DEFAULT_DB_PATH, readonly: bool = True
            ) -> sqlite3.Connection:
    """
    Открыть соединение с БД
    Args:
        path: путь к файлу SQLite. По умолчанию - data/vulndb.sqlite
        readonly: открыть в режиме только для чтения (sqlite URI ?mode=ro)
    Returns:
        sqlite3.Connection с row_factory = sqlite3.Row
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(
            f"Нет БД: {p}. Сначала запустите: python -m src.loader"
        )
    if readonly:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    else:
        con = sqlite3.connect(p)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def find_products(con: sqlite3.Connection, product_name: str,
                  vendor_name: str | None = None) -> list[sqlite3.Row]:
    """
    Найти продукты с заданным именем (опционально - у конкретного вендора)
    Args:
        con: соединение
        product_name: точное имя продукта
        vendor_name: если задано - фильтрует по вендору
    Returns:
        Список строк с полями product_id, product, vendor. Пустой список, если
        ничего не найдено
    """
    if vendor_name is not None:
        cur = con.execute(
            """
            SELECT p.id AS product_id, p.name AS product, v.name AS vendor
            FROM products p JOIN vendors v ON v.id = p.vendor_id
            WHERE p.name = ? AND v.name = ?
            ORDER BY v.name
            """,
            (product_name, vendor_name),
        )
    else:
        cur = con.execute(
            """
            SELECT p.id AS product_id, p.name AS product, v.name AS vendor
            FROM products p JOIN vendors v ON v.id = p.vendor_id
            WHERE p.name = ?
            ORDER BY v.name
            """,
            (product_name,),
        )
    return cur.fetchall()


def list_all_products(con: sqlite3.Connection) -> list[sqlite3.Row]:
    """
    Все продукты для справки (например, для `cli list-products`)
    Args:
        con: соединение
    Returns:
        Список строк с полями product_id, product, vendor
    """
    return con.execute(
        """
        SELECT p.id AS product_id, p.name AS product, v.name AS vendor
        FROM products p JOIN vendors v ON v.id = p.vendor_id
        ORDER BY v.name, p.name
        """
    ).fetchall()


def get_versions(con: sqlite3.Connection, product_id: int) -> list[str]:
    """
    Все версии продукта из фида versions (в порядке as-is из фида)
    Args:
        con: соединение
        product_id: первичный ключ продукта
    Returns:
        Список строк версий, возможно не отсортированный. Сортировку делает
        логика через cmp_version
    """
    rows = con.execute(
        "SELECT version FROM versions WHERE product_id = ?",
        (product_id,),
    ).fetchall()
    return [r['version'] for r in rows]


def get_vulnerabilities(con: sqlite3.Connection, product_id: int
                        ) -> list[sqlite3.Row]:
    """
    Все записи об уязвимостях продукта
    Args:
        con: соединение
        product_id: первичный ключ продукта
    Returns:
        Строки с полями kla_id, description, publish_date,
        start_vuln_version, fixed_version
    """
    return con.execute(
        """
        SELECT kla_id, description, publish_date,
               start_vuln_version, fixed_version
        FROM vulnerabilities
        WHERE product_id = ?
        """,
        (product_id,),
    ).fetchall()
