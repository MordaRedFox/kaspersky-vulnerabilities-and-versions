"""
Интеграционные тесты: проверяют, что загруженная БД соответствует фидам
Порядок запуска:
  1) python -m src.loader      # пересобрать БД, если фиды менялись
  2) pytest -v                 # проверить, что БД соответствует фидам
"""

import json
import re
import sqlite3
from pathlib import Path
import pytest


ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / 'data' / 'vulndb.sqlite'
FEED_VERSIONS = ROOT / 'feed' / 'versions.json'
FEED_VULNS = ROOT / 'feed' / 'vulnerabilities.json'


@pytest.fixture(scope='session')
def loaded_db():
    """
    Read-only соединение с data/vulndb.sqlite
    """
    if not DB_PATH.is_file():
        pytest.fail(
            f"Нет БД: {DB_PATH}. Сначала запустите: python -m src.loader")
    con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
    finally:
        con.close()


@pytest.fixture(scope='session')
def feed_versions():
    """
    Распарсенный feed/versions.json (только чтение)
    """
    if not FEED_VERSIONS.is_file():
        pytest.skip(f"Нет фида: {FEED_VERSIONS}")
    return json.loads(FEED_VERSIONS.read_text(encoding='utf-8'))


@pytest.fixture(scope="session")
def feed_vulns():
    """
    Распарсенный feed/vulnerabilities.json (только чтение)
    """
    if not FEED_VULNS.is_file():
        pytest.skip(f"Нет фида: {FEED_VULNS}")
    return json.loads(FEED_VULNS.read_text(encoding='utf-8'))


def test_db_is_fresh():
    """
    Предупреждает, если код загрузчика или фиды новее, чем БД
    """
    if not DB_PATH.is_file():
        pytest.fail(f"Нет БД: {DB_PATH}. Запустите: python -m src.loader")
    db_mtime = DB_PATH.stat().st_mtime
    sources = [
        ROOT / 'src' / 'loader.py',
        ROOT / 'schema.sql',
        FEED_VERSIONS,
        FEED_VULNS,
    ]
    stale = [
        p.name for p in sources
        if p.is_file() and p.stat().st_mtime > db_mtime
    ]
    assert not stale, (
        f"БД старше исходников ({', '.join(stale)}). "
        f"Пересоберите: python -m src.loader"
    )


def test_db_is_read_only(loaded_db):
    """
    Подтверждает, что соединение открыто в режиме read-only
    """
    with pytest.raises(sqlite3.OperationalError, match='readonly'):
        loaded_db.execute("INSERT INTO vendors(name) VALUES ('__test__')")


# Тесты структуры БД


def test_db_file_created():
    assert DB_PATH.is_file()
    assert DB_PATH.stat().st_size > 0


def test_all_tables_exist(loaded_db):
    rows = loaded_db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    tables = {r['name'] for r in rows}
    assert {'vendors', 'products', 'versions', 'vulnerabilities'} <= tables


def test_indexes_exist(loaded_db):
    rows = loaded_db.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
    ).fetchall()
    indexes = {r['name'] for r in rows}
    assert {
        'idx_versions_product',
        'idx_vulns_product',
        'idx_vulns_kla',
    } <= indexes


# Тесты полноты загрузки - счетчики против исходных фидов


def test_versions_count_matches_source(loaded_db, feed_versions):
    db_count = loaded_db.execute("SELECT COUNT(*) FROM versions").fetchone()[0]
    assert db_count == len(feed_versions)


def test_vulns_count_matches_source(loaded_db, feed_vulns):
    db_count = loaded_db.execute(
        "SELECT COUNT(*) FROM vulnerabilities"
    ).fetchone()[0]
    assert db_count == len(feed_vulns)


def test_vendors_count(loaded_db, feed_versions, feed_vulns):
    expected = {r['vendor'] for r in feed_versions}
    expected |= {r['vendor'] for r in feed_vulns}
    db_count = loaded_db.execute("SELECT COUNT(*) FROM vendors").fetchone()[0]
    assert db_count == len(expected)


def test_products_count(loaded_db, feed_versions, feed_vulns):
    expected = {(r['vendor'], r['product']) for r in feed_versions}
    expected |= {(r['vendor'], r['product']) for r in feed_vulns}
    db_count = loaded_db.execute("SELECT COUNT(*) FROM products").fetchone()[0]
    assert db_count == len(expected)


def test_distinct_kla_count(loaded_db, feed_vulns):
    expected = {r['KLA_id'] for r in feed_vulns}
    db_count = loaded_db.execute(
        "SELECT COUNT(DISTINCT kla_id) FROM vulnerabilities"
    ).fetchone()[0]
    assert db_count == len(expected)


# Тесты дубликатов


def test_no_duplicate_versions(loaded_db):
    dupes = loaded_db.execute(
        "SELECT product_id, version, COUNT(*) AS c "
        "FROM versions "
        "GROUP BY product_id, version HAVING c > 1"
    ).fetchall()
    assert dupes == []


def test_no_duplicate_vuln_rows(loaded_db):
    dupes = loaded_db.execute(
        "SELECT product_id, kla_id, start_vuln_version, fixed_version, "
        "       COUNT(*) AS c "
        "FROM vulnerabilities "
        "GROUP BY product_id, kla_id, start_vuln_version, fixed_version "
        "HAVING c > 1"
    ).fetchall()
    assert dupes == []


# Тесты мультификсов одного KLA (одна уязвимость, но много веток)


@pytest.mark.parametrize('kla_id, expected_rows', [
    ('KLA67449', 7),  # Git for Windows  7 фиксов в разных ветках
    ('KLA77143', 5),  # PostgreSQL       5 фиксов
    ('KLA71453', 4),  # PostgreSQL       4 фикса
    ('KLA73989', 2),  # Thunderbird      2 фикса
    ('KLA79193', 2),  # VirtualBox       2 фикса
])
def test_multi_fix_klAs_have_expected_rows(loaded_db, kla_id, expected_rows):
    n = loaded_db.execute(
        "SELECT COUNT(*) FROM vulnerabilities WHERE kla_id = ?", (kla_id,)
    ).fetchone()[0]
    assert n == expected_rows


def test_multi_fix_kla_67449_fixes(loaded_db):
    rows = loaded_db.execute(
        "SELECT DISTINCT fixed_version FROM vulnerabilities WHERE kla_id = 'KLA67449'"
    ).fetchall()
    fixes = {r['fixed_version'] for r in rows}
    assert fixes == {
        '2.39.4', '2.40.2', '2.41.1', '2.42.2', '2.43.4', '2.44.1', '2.45.1',
    }


# Точечные "эталонные" записи


def test_postgresql_kla52239_present(loaded_db):
    row = loaded_db.execute(
        "SELECT v.start_vuln_version, v.fixed_version "
        "FROM vulnerabilities v JOIN products p ON p.id = v.product_id "
        "WHERE p.name = 'PostgreSQL' AND v.kla_id = 'KLA52239'"
    ).fetchone()
    assert row is not None
    assert row['start_vuln_version'] == '15'
    assert row['fixed_version'] == '15.4.1'


def test_vlc_kla66427_fix_is_3_0_19(loaded_db):
    row = loaded_db.execute(
        "SELECT v.fixed_version "
        "FROM vulnerabilities v JOIN products p ON p.id = v.product_id "
        "WHERE p.name = 'VLC media player' AND v.kla_id = 'KLA66427'"
    ).fetchone()
    assert row is not None
    assert row['fixed_version'] == '3.0.19'


# Целостность FK


def test_foreign_keys_no_violations(loaded_db):
    assert loaded_db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_all_products_have_vendor(loaded_db):
    orphans = loaded_db.execute(
        "SELECT COUNT(*) FROM products p "
        "LEFT JOIN vendors v ON v.id = p.vendor_id "
        "WHERE v.id IS NULL"
    ).fetchone()[0]
    assert orphans == 0


def test_all_versions_have_product(loaded_db):
    orphans = loaded_db.execute(
        "SELECT COUNT(*) FROM versions vs "
        "LEFT JOIN products p ON p.id = vs.product_id "
        "WHERE p.id IS NULL"
    ).fetchone()[0]
    assert orphans == 0


def test_all_vulns_have_product(loaded_db):
    orphans = loaded_db.execute(
        "SELECT COUNT(*) FROM vulnerabilities vu "
        "LEFT JOIN products p ON p.id = vu.product_id "
        "WHERE p.id IS NULL"
    ).fetchone()[0]
    assert orphans == 0


# Санитизация данных


def test_publish_date_format(loaded_db):
    rows = loaded_db.execute(
        "SELECT publish_date FROM vulnerabilities WHERE publish_date IS NOT NULL"
    ).fetchall()
    for r in rows:
        assert re.fullmatch(
            r'\d{4}-\d{2}-\d{2}', r['publish_date']), r['publish_date']


def test_required_fields_not_null(loaded_db):
    n = loaded_db.execute(
        "SELECT COUNT(*) FROM vulnerabilities "
        "WHERE kla_id IS NULL "
        "   OR start_vuln_version IS NULL "
        "   OR fixed_version IS NULL"
    ).fetchone()[0]
    assert n == 0


# "Похожие" продукты это разные записи, не алиасы


@pytest.mark.parametrize('vendor, expected_pair', [
    ('VideoLAN',            {'VLC media player', 'VLC media player (MSI installer)'}),
    ('Foxit Corporation',   {'Foxit Reader', 'Foxit Reader Enterprise'}),
    ('7-Zip Developers',    {'7-Zip', '7-Zip (MSI installer)'}),
    ('Google',              {'Google Chrome', 'Google Chrome Enterprise'}),
])
def test_similar_products_are_distinct(loaded_db, vendor, expected_pair):
    rows = loaded_db.execute(
        "SELECT p.name FROM products p JOIN vendors v ON v.id = p.vendor_id "
        "WHERE v.name = ?", (vendor,)
    ).fetchall()
    names = {r['name'] for r in rows}
    assert expected_pair <= names
