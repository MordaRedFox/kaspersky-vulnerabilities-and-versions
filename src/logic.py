"""
Бизнес-логика: безопасные версии и уязвимости для конкретной версии.
Использует src.db для доступа к данным и src.versions для сравнения
"""

import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from functools import cmp_to_key
from src import db
from src.versions import cmp_version, is_vulnerable


@dataclass
class ProductRef:
    """
    Однозначная ссылка на продукт
    """
    product_id: int
    vendor: str
    product: str


@dataclass
class VulnRecord:
    """
    Одна уязвимость (KLA) с полным набором фиксов
    """
    kla_id: str
    description: str | None
    publish_date: str | None
    fixes: list[str]
    ranges: list[tuple[str, str]]


@dataclass
class SafeVersionsResult:
    """
    Результат поиска безопасных версий продукта
    """
    product: ProductRef
    safe_versions: list[str]


@dataclass
class VulnsResult:
    """
    Результат поиска уязвимостей для конкретной версии продукта
    """
    product: ProductRef
    version: str
    vulns: list[VulnRecord]


class ProductNotFoundError(LookupError):
    """
    Продукт с таким именем (и вендором) не найден
    """


class AmbiguousProductError(LookupError):
    """
    Найдено несколько продуктов с одинаковым именем - нужен --vendor
    """

    def __init__(self, name: str, candidates: list[ProductRef]):
        self.name = name
        self.candidates = candidates
        names = ", ".join(f"{c.vendor!r}" for c in candidates)
        super().__init__(
            f"Несколько продуктов с именем {name!r}. Уточните через --vendor: {names}")


def resolve_product(con: sqlite3.Connection, product_name: str,
                    vendor_name: str | None = None) -> ProductRef:
    """
    Найти единственный продукт по имени
    Args:
        con: соединение
        product_name: точное имя продукта
        vendor_name: если задано - фильтрует по вендору
    Returns:
        ProductRef на найденный продукт
    """
    rows = db.find_products(con, product_name, vendor_name)
    if not rows:
        hint = f' (vendor={vendor_name!r})' if vendor_name else ''
        raise ProductNotFoundError(f"Продукт {product_name!r}{hint} не найден")
    if len(rows) > 1:
        candidates = [
            ProductRef(r['product_id'], r['vendor'], r['product'])
            for r in rows
        ]
        raise AmbiguousProductError(product_name, candidates)
    r = rows[0]
    return ProductRef(r['product_id'], r['vendor'], r['product'])


def safe_versions(con: sqlite3.Connection, product_name: str,
                  vendor_name: str | None = None) -> SafeVersionsResult:
    """
    Версии продукта, которые не попадают ни в один диапазон уязвимостей
    Args:
        con: соединение
        product_name: точное имя продукта
        vendor_name: если задано - фильтрует по вендору
    Returns:
        SafeVersionsResult с отсортированным по возрастанию списком версий
    """
    product = resolve_product(con, product_name, vendor_name)
    versions = db.get_versions(con, product.product_id)
    vulns = db.get_vulnerabilities(con, product.product_id)
    safe: list[str] = []
    for v in versions:
        vulnerable = any(
            is_vulnerable(v, row['start_vuln_version'], row['fixed_version'])
            for row in vulns
        )
        if not vulnerable:
            safe.append(v)
    safe.sort(key=cmp_to_key(cmp_version))
    return SafeVersionsResult(product=product, safe_versions=safe)


def vulns_for(con: sqlite3.Connection, product_name: str, version: str,
              vendor_name: str | None = None) -> VulnsResult:
    """
    Уязвимости, актуальные для конкретной версии продукта
    Один KLA выводится одной записью со всеми своими fixed_version -
    чтобы было видно, в каких ветках уязвимость закрыта
    Args:
        con: соединение
        product_name: точное имя продукта
        version: проверяемая версия
        vendor_name: если задано - фильтрует по вендору
    Returns:
        VulnsResult со списком VulnRecord, отсортированным по kla_id
    """
    product = resolve_product(con, product_name, vendor_name)
    rows = db.get_vulnerabilities(con, product.product_id)
    by_kla: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        by_kla[row['kla_id']].append(row)
    result: list[VulnRecord] = []
    for kla_id, kla_rows in by_kla.items():
        matched = [
            row for row in kla_rows
            if is_vulnerable(
                version, row['start_vuln_version'], row['fixed_version'])
        ]
        if not matched:
            continue
        fixes = sorted(
            {row['fixed_version'] for row in kla_rows},
            key=cmp_to_key(cmp_version),
        )
        ranges = [
            (row['start_vuln_version'], row['fixed_version'])
            for row in kla_rows
        ]
        result.append(VulnRecord(
            kla_id=kla_id,
            description=kla_rows[0]['description'],
            publish_date=kla_rows[0]['publish_date'],
            fixes=fixes,
            ranges=ranges,
        ))
    result.sort(key=lambda r: r.kla_id)
    return VulnsResult(product=product, version=version, vulns=result)
