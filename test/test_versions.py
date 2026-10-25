"""
Юнит-тесты парсера и сравнения версий
БД не нужна - модуль чисто вычислительный. Кейсы взяты из реальных фидов
"""

import sys
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from src.versions import cmp_version, is_vulnerable, parse_version


class TestParseVersion:
    @pytest.mark.parametrize('raw, expected', [
        ('0', (0,)),
        ('15', (15,)),
        ('9.7', (9, 7)),
        ('9.65', (9, 65)),
        ('3.0.11', (3, 0, 11)),
        ('2.41.0.2', (2, 41, 0, 2)),
        ('2024.1.0.23997', (2024, 1, 0, 23997)),
        ('8.0.1010.13', (8, 0, 1010, 13)),
        ('24.01', (24, 1)),
        ('  1.2  ', (1, 2)),
        ('128.4.0', (128, 4, 0)),
    ])
    def test_valid(self, raw: str, expected: tuple[int, ...]) -> None:
        assert parse_version(raw) == expected

    @pytest.mark.parametrize('raw', [
        '', ' ', '.', '..', '1.', '.1', '1..2',
        'abc', '1.a', 'a.1', '1.2-rc1', 'v1.2', '1,2',
        '+1', '-1', '1_0', '１', '１.2',  # unicode digit
    ])
    def test_invalid(self, raw: str) -> None:
        with pytest.raises(ValueError):
            parse_version(raw)


class TestCmpVersion:
    @pytest.mark.parametrize('a, b', [
        ('1.0', '1.0.0'),
        ('1', '1.0'),
        ('15', '15.0.0'),
        ('0', '0.0.0'),
        ('2.41.0', '2.41.0.0'),
        ('128.4', '128.4.0'),
        ('9.7', '9.7'),
        ('9.65', '9.65'),
        ('24.09', '24.09'),
    ])
    def test_equal_with_padding(self, a: str, b: str) -> None:
        assert cmp_version(a, b) == 0

    @pytest.mark.parametrize('a, b, expected', [
        # Числовое, не лексикографическое, сравнение
        ('1.0.9', '1.0.10', -1),
        ('1.0.10', '1.0.9', 1),
        ('3.0.9', '3.0.11', -1),
        ('3.0.11', '3.0.9', 1),
        ('2.9', '2.10', -1),
        ('2.10', '2.11', -1),
        ('9.7', '9.70', -1),  # числово: 7 < 70
        # Паддинг нулями
        ('15', '15.0.1', -1),
        ('2.41.0', '2.41.0.2', -1),
        ('128.4', '128.4.0.1', -1),
        # Реальные фидовые значения
        ('0', '3.0.19', -1),
        ('2024.1.0.23997', '2024.2.0.25138', -1),
        ('8.0.4210.9', '8.0.4310.10', -1),
        ('2.39.2', '2.39.4', -1),
        ('12.21.1', '12.22.1', -1),
        ('15.9.1', '17.1.1', -1),
        # 2-компонентные: чисто числовое сравнение
        ('24.01', '24.09', -1),
        ('24.08', '24.09', -1),
        ('2.25', '2.30', -1),
        ('2.30', '2.40', -1),
        ('2.39', '2.40', -1),
        ('0.81', '0.82', -1),
        # UltraISO: числовая интерпретация (см. README)
        # 9.65 > 9.7, потому что 65 > 7 - это баг в данных,
        # мы его не чиним, а документируем
        ('9.7', '9.65', -1),
        ('9.65', '9.7', 1),
        ('9.65', '9.66', -1),
        ('9.71', '9.72', -1),
    ])
    def test_order(self, a: str, b: str, expected: int) -> None:
        assert cmp_version(a, b) == expected

    def test_antisymmetry(self) -> None:
        for a, b in [
            ('3.0.11', '3.0.9'),
            ('9.65', '9.7'),
            ('24.09', '24.10'),
            ('2.30', '2.40'),
        ]:
            assert cmp_version(a, b) == -cmp_version(b, a)

    def test_reflexivity(self) -> None:
        for v in ['0', '15', '3.0.11', '2024.1.0.23997', '9.65', '24.09']:
            assert cmp_version(v, v) == 0


class TestIsVulnerable:
    @pytest.mark.parametrize('version, start, fix, expected', [
        # PostgreSQL KLA52239: [15, 15.4.1)
        ('14.9.1', '15', '15.4.1', False),
        ('15',     '15', '15.4.1', True),
        ('15.0.1', '15', '15.4.1', True),
        ('15.3.1', '15', '15.4.1', True),
        ('15.4.0.9', '15', '15.4.1', True),
        ('15.4.1', '15', '15.4.1', False),
        ('15.4.2', '15', '15.4.1', False),
        ('17.1.1', '15', '15.4.1', False),
        # VLC media player KLA66427: [0, 3.0.19)
        ('0.0.1', '0', '3.0.19', True),
        ('3.0.18', '0', '3.0.19', True),
        ('3.0.19', '0', '3.0.19', False),
        ('3.0.20', '0', '3.0.19', False),
        # 7-Zip KLA77436: [0, 24.07)
        ('24.01', '0', '24.07', True),
        ('24.06', '0', '24.07', True),
        ('24.07', '0', '24.07', False),
        ('24.08', '0', '24.07', False),
        ('24.09', '0', '24.07', False),
        # UltraISO KLA11360: [9, 9.7)
        # ИЗВЕСТНОЕ ОГРАНИЧЕНИЕ (см. README): при чисто числовой
        # интерпретации 9.65 > 9.7, поэтому 9.65 и 9.66 ошибочно
        # считаются 'безопасными'. Это баг в данных, не в коде
        ('9.65', '9', '9.7', False),
        ('9.66', '9', '9.7', False),
        ('9.7',  '9', '9.7', False),
        ('9.71', '9', '9.7', False),
        ('9.75', '9', '9.7', False),
        ('9.0',  '9', '9.7', True),
        ('8.99', '9', '9.7', False),
        # KeePass KLA11362: [2, 2.34)
        ('2.25', '2', '2.34', True),
        ('2.30', '2', '2.34', True),
        ('2.33', '2', '2.34', True),
        ('2.34', '2', '2.34', False),
        ('2.40', '2', '2.34', False),
        # PuTTY KLA65599: [0, 0.81)
        ('0.80', '0', '0.81', True),
        ('0.81', '0', '0.81', False),
        ('0.82', '0', '0.81', False),
        # Oracle VirtualBox KLA79193 (ветка 7.1): [7.1, 7.1.6)
        ('7.0.10', '7.1', '7.1.6', False),
        ('7.1.0',  '7.1', '7.1.6', True),
        ('7.1.4',  '7.1', '7.1.6', True),
        ('7.1.6',  '7.1', '7.1.6', False),
        # Apache Tomcat KLA11495: [9, 9.0.15)
        ('8.5.100', '9', '9.0.15', False),
        ('9.0.14',  '9', '9.0.15', True),
        ('9.0.15',  '9', '9.0.15', False),
        # Git for Windows KLA67449 (ветка 2.39): [0, 2.39.4)
        ('2.39.0', '0', '2.39.4', True),
        ('2.39.2', '0', '2.39.4', True),
        ('2.39.4', '0', '2.39.4', False),
    ])
    def test_cases(self, version: str, start: str, fix: str,
                   expected: bool,) -> None:
        assert is_vulnerable(version, start, fix) is expected

    def test_boundary_start_inclusive(self) -> None:
        assert is_vulnerable('15', '15', '15.4.1') is True

    def test_boundary_fix_exclusive(self) -> None:
        assert is_vulnerable('15.4.1', '15', '15.4.1') is False

    def test_equal_start_and_fix_makes_no_version_vulnerable(self) -> None:
        for v in ['0', '1.0', '10.0.0']:
            assert is_vulnerable(v, '5.0', '5.0') is False


def test_ultraiso_known_data_bug() -> None:
    """
    Документирует баг в данных UltraISO, который осознанно не чинится
    В фиде versions.json у UltraISO версии записаны как "9.65", "9.66",
    "9.7", "9.71". Вендор, судя по прогрессии, имеет в виду "9.6.5",
    "9.6.6", "9.7.0", "9.7.1". Но в фиде эти версии "слипшиеся":
    две компоненты вместо трех (см. README, раздел "Известные ограничения").
    Мы трактуем их чисто числово (65 > 7), поэтому 9.65 и 9.66
    ошибочно считаются "безопасными" по KLA11360 (диапазон [9, 9.7)),
    хотя по задумке вендора они уязвимы
    """
    assert is_vulnerable('9.65', '9', '9.7') is False  # баг данных
    assert is_vulnerable('9.66', '9', '9.7') is False  # баг данных
