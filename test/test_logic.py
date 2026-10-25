"""
Интеграционные тесты бизнес-логики на реальной БД
БД открывается в режиме read-only. Порядок запуска:
  1) python -m src.loader     (если фиды менялись)
  2) pytest -v
"""

import sqlite3
import sys
from functools import cmp_to_key
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import pytest
from src import db, logic
from src.versions import cmp_version, is_vulnerable


DB_PATH = ROOT / 'data' / 'vulndb.sqlite'


@pytest.fixture(scope='session')
def con():
    if not DB_PATH.is_file():
        pytest.fail(f"Нет БД: {DB_PATH}. Запустите: python -m src.loader")
    c = db.open_db(DB_PATH, readonly=True)
    try:
        yield c
    finally:
        c.close()


def test_open_db_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        db.open_db(tmp_path / 'nonexistent.sqlite')


def test_open_db_readonly(con):
    with pytest.raises(sqlite3.OperationalError, match='readonly'):
        con.execute("INSERT INTO vendors(name) VALUES ('__test__')")


def test_resolve_product_found(con):
    p = logic.resolve_product(con, 'PostgreSQL')
    assert p.product == 'PostgreSQL'
    assert p.vendor == 'Postgresql'


def test_resolve_product_not_found(con):
    with pytest.raises(logic.ProductNotFoundError):
        logic.resolve_product(con, 'Nonexistent Product')


def test_resolve_product_with_vendor(con):
    p = logic.resolve_product(con, 'PostgreSQL', 'Postgresql')
    assert p.product == 'PostgreSQL'


def test_resolve_product_wrong_vendor(con):
    with pytest.raises(logic.ProductNotFoundError):
        logic.resolve_product(con, 'PostgreSQL', 'Wrong Vendor')


def test_safe_versions_invariants(con):
    """
    Все safe-версии не попадают в диапазоны, а не-safe - попадают
    """
    result = logic.safe_versions(con, 'PostgreSQL')
    versions = db.get_versions(con, result.product.product_id)
    vulns = db.get_vulnerabilities(con, result.product.product_id)
    safe_set = set(result.safe_versions)
    assert safe_set <= set(versions)
    for v in result.safe_versions:
        assert not any(
            is_vulnerable(v, r['start_vuln_version'], r['fixed_version'])
            for r in vulns
        ), f"safe-версия {v} попадает в диапазон уязвимости"
    for v in versions:
        if v in safe_set:
            continue
        assert any(
            is_vulnerable(v, r['start_vuln_version'], r['fixed_version'])
            for r in vulns
        ), f"не-safe версия {v} не попадает ни в один диапазон"


def test_safe_versions_sorted(con):
    """
    Список safe-версий отсортирован по возрастанию (через cmp_version)
    """
    result = logic.safe_versions(con, 'VLC media player')
    expected = sorted(result.safe_versions, key=cmp_to_key(cmp_version))
    assert result.safe_versions == expected


def test_safe_versions_vlc_3_0_19_is_safe(con):
    """
    KLA66427: [0, 3.0.19). Значит 3.0.19 safe, 3.0.18 нет
    """
    result = logic.safe_versions(con, 'VLC media player')
    assert '3.0.19' in result.safe_versions
    assert '3.0.18' not in result.safe_versions


def test_vulns_postgresql_15_3_1_in_kla52239(con):
    result = logic.vulns_for(con, 'PostgreSQL', '15.3.1')
    kla_ids = {v.kla_id for v in result.vulns}
    assert 'KLA52239' in kla_ids


def test_vulns_postgresql_17_1_1_not_in_kla52239(con):
    """
    17.1.1 > 15.4.1 - не попадает в KLA52239
    """
    result = logic.vulns_for(con, 'PostgreSQL', '17.1.1')
    kla_ids = {v.kla_id for v in result.vulns}
    assert 'KLA52239' not in kla_ids


def test_vulns_git_2_39_2_has_all_7_fixes(con):
    """
    KLA67449 - мультификс; для 2.39.2 должны быть все 7 фиксов
    """
    result = logic.vulns_for(con, 'Git for Windows', '2.39.2')
    rec = next((v for v in result.vulns if v.kla_id == 'KLA67449'), None)
    assert rec is not None
    assert len(rec.fixes) == 7
    assert '2.39.4' in rec.fixes
    assert '2.45.1' in rec.fixes


def test_vulns_klAs_are_deduplicated(con):
    """
    Каждая KLA встречается в результате не более одного раза
    """
    result = logic.vulns_for(con, 'Git for Windows', '2.39.2')
    kla_ids = [v.kla_id for v in result.vulns]
    assert len(kla_ids) == len(set(kla_ids))


def test_vulns_empty_for_safe_version(con):
    """
    Если версия безопасна - vulns_for возвращает пустой список
    """
    result = logic.vulns_for(con, 'VLC media player', '3.0.19')
    assert result.vulns == []


def test_vulns_each_range_is_valid(con):
    """
    У каждой KLA в ranges валидные (start, fix) пары, и хоть одна матчится
    """
    result = logic.vulns_for(con, 'PostgreSQL', '15.3.1')
    for rec in result.vulns:
        assert rec.ranges
        assert any(
            is_vulnerable(result.version, start, fix)
            for start, fix in rec.ranges
        ), f"{rec.kla_id}: ни один диапазон не матчится для {result.version}"
