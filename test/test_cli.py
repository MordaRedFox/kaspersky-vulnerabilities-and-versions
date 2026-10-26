"""
Тесты CLI: one-shot через main(argv), REPL через run_repl(read_line=...),
корневой main.py - через subprocess. БД открывается read-only.
"""

import json
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import pytest
from src import cli, db


DB_PATH = ROOT / 'data' / 'vulndb.sqlite'


@pytest.fixture(scope='session', autouse=True)
def _require_db():
    if not DB_PATH.is_file():
        pytest.fail(f"Нет БД: {DB_PATH}. Запустите: python -m src.loader")


@pytest.fixture
def args():
    """
    Собрать argv с --db перед подкомандой (для one-shot режима)
    """
    def _make(*rest: str) -> list[str]:
        return ['--db', str(DB_PATH), *rest]
    return _make


@pytest.fixture
def con():
    """
    Открытое read-only соединение для тестов REPL
    """
    c = db.open_db(DB_PATH, readonly=True)
    try:
        yield c
    finally:
        c.close()


def _make_reader(lines: list[str]):
    """
    Сделать read_line для run_repl, отдающий строки по одной
    """
    it = iter(lines)
    return lambda prompt='': next(it)


# ---------------------------------------------------------------------------
# safe-versions (one-shot)
# ---------------------------------------------------------------------------

def test_safe_versions_text(args, capsys):
    rc = cli.main(args('safe-versions', 'VLC media player'))
    out = capsys.readouterr().out
    assert rc == 0
    assert '3.0.19' in out
    assert '3.0.18' not in out  # 3.0.18 уязвима


def test_safe_versions_json(args, capsys):
    rc = cli.main(args('safe-versions', 'VLC media player', '--json'))
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload['product'] == 'VLC media player'
    assert payload['vendor'] == 'VideoLAN'
    assert '3.0.19' in payload['safe_versions']


def test_safe_versions_latest(args, capsys):
    rc = cli.main(args('safe-versions', 'VLC media player', '--latest', '--json'))
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert len(payload['safe_versions']) == 1
    # Максимальная безопасная версия VLC в фиде
    assert payload['safe_versions'][0] == '3.0.21'


def test_safe_versions_not_found(args, capsys):
    rc = cli.main(args('safe-versions', 'Nonexistent Product'))
    err = capsys.readouterr().err
    assert rc == 1
    assert 'не найден' in err


# One-short


def test_vulns_text(args, capsys):
    rc = cli.main(args('vulns', 'PostgreSQL', '15.3.1'))
    out = capsys.readouterr().out
    assert rc == 0
    assert 'KLA52239' in out
    assert '15.4.1' in out


def test_vulns_json(args, capsys):
    rc = cli.main(args('vulns', 'PostgreSQL', '15.3.1', '--json'))
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload['product'] == 'PostgreSQL'
    assert payload['version'] == '15.3.1'
    kla_ids = {v['kla_id'] for v in payload['vulns']}
    assert 'KLA52239' in kla_ids


def test_vulns_multifix_all_fixes_shown(args, capsys):
    """
    KLA67449 у Git - 7 фиксов, все должны быть в JSON
    """
    rc = cli.main(args('vulns', 'Git for Windows', '2.39.2', '--json'))
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    rec = next(v for v in payload['vulns'] if v['kla_id'] == 'KLA67449')
    assert len(rec['fixes']) == 7


def test_vulns_no_vulns(args, capsys):
    rc = cli.main(args('vulns', 'VLC media player', '3.0.19'))
    out = capsys.readouterr().out
    assert rc == 0
    assert 'уязвимостей не найдено' in out


def test_vulns_invalid_version(args, capsys):
    rc = cli.main(args('vulns', 'PostgreSQL', 'not-a-version'))
    err = capsys.readouterr().err
    assert rc == 2
    assert 'Некорректная версия' in err


def test_vulns_product_not_found(args, capsys):
    rc = cli.main(args('vulns', 'Nonexistent', '1.0'))
    err = capsys.readouterr().err
    assert rc == 1
    assert 'не найден' in err


def test_list_products_text(args, capsys):
    rc = cli.main(args('list-products'))
    out = capsys.readouterr().out
    assert rc == 0
    assert 'PostgreSQL' in out
    assert 'VLC media player' in out


def test_list_products_json(args, capsys):
    rc = cli.main(args('list-products', '--json'))
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert isinstance(payload, list)
    products = {r['product'] for r in payload}
    assert 'PostgreSQL' in products
    assert 'VLC media player' in products


def test_db_missing(tmp_path, capsys):
    rc = cli.main(['--db', str(tmp_path / 'nope.sqlite'), 'list-products'])
    err = capsys.readouterr().err
    assert rc == 1
    assert 'Нет БД' in err


def test_main_no_args_prints_help(capsys):
    """
    main([]) без аргументов печатает справку и возвращает 2
    """
    rc = cli.main([])
    err = capsys.readouterr().err
    assert rc == 2
    assert 'safe-versions' in err
    assert 'vulns' in err
    assert 'list-products' in err


# REPL


def test_repl_quit_by_exit(con, capsys):
    cli.run_repl(con, read_line=_make_reader(['exit']))
    out = capsys.readouterr().out
    assert 'Запуск в интерактивном режиме' in out


def test_repl_quit_by_quit(con):
    cli.run_repl(con, read_line=_make_reader(['quit']))


def test_repl_quit_by_q(con):
    cli.run_repl(con, read_line=_make_reader(['q']))


def test_repl_quit_by_eof(con):
    """
    Пустой итератор = StopIteration = EOF
    """
    cli.run_repl(con, read_line=_make_reader([]))


def test_repl_runs_command(con, capsys):
    cli.run_repl(con, read_line=_make_reader(['list-products', 'exit']))
    out = capsys.readouterr().out
    assert 'PostgreSQL' in out


def test_repl_help(con, capsys):
    cli.run_repl(con, read_line=_make_reader(['help', 'exit']))
    out = capsys.readouterr().out
    assert 'safe-versions' in out
    assert 'list-products' in out


def test_repl_help_question_mark(con, capsys):
    cli.run_repl(con, read_line=_make_reader(['?', 'exit']))
    out = capsys.readouterr().out
    assert 'safe-versions' in out


def test_repl_safe_versions(con, capsys):
    cli.run_repl(
        con,
        read_line=_make_reader(['safe-versions "VLC media player"', 'exit']),
    )
    out = capsys.readouterr().out
    assert '3.0.19' in out


def test_repl_vulns(con, capsys):
    cli.run_repl(
        con,
        read_line=_make_reader(["vulns 'PostgreSQL' '15.3.1'", 'exit']),
    )
    out = capsys.readouterr().out
    assert 'KLA52239' in out


def test_repl_quoted_args(con, capsys):
    """
    shlex.split обрабатывает кавычки: имя продукта с пробелом
    """
    cli.run_repl(
        con,
        read_line=_make_reader(
            ["safe-versions 'VLC media player' --json", 'exit']),
    )
    out = capsys.readouterr().out
    assert '"VLC media player"' in out


def test_repl_bad_command_does_not_stop(con, capsys):
    """
    Опечатка в команде не должна ронять REPL
    """
    cli.run_repl(
        con,
        read_line=_make_reader(
            ['nonexistent-command', 'list-products', 'exit']),
    )
    out = capsys.readouterr().out
    assert 'PostgreSQL' in out


def test_repl_invalid_version_does_not_stop(con, capsys):
    cli.run_repl(
        con,
        read_line=_make_reader(
            ["vulns 'PostgreSQL' 'not-a-version'", 'list-products', 'exit']),
    )
    out = capsys.readouterr().out
    assert 'PostgreSQL' in out


def test_repl_empty_lines_are_ignored(con, capsys):
    cli.run_repl(
        con,
        read_line=_make_reader(['', '   ', 'list-products', 'exit']),
    )
    out = capsys.readouterr().out
    assert 'PostgreSQL' in out


# Entrypoint и main

def test_entrypoint_no_args_runs_repl(monkeypatch):
    """
    entrypoint([]) не блокирует: подменяем run_repl в src.cli.app
    """
    called = {'repl': False}

    def fake_repl(con, read_line=None):
        called['repl'] = True

    monkeypatch.setattr('src.cli.app.run_repl', fake_repl)
    rc = cli.entrypoint([])
    assert rc == 0
    assert called['repl'] is True


def test_entrypoint_with_args_runs_one_shot(monkeypatch):
    """
    entrypoint(['list-products']) идет в main(), а не в REPL
    """
    called = {'main': None}

    def fake_main(argv):
        called['main'] = argv
        return 0

    monkeypatch.setattr('src.cli.app.main', fake_main)
    rc = cli.entrypoint(['--db', str(DB_PATH), 'list-products'])
    assert rc == 0
    assert called['main'] is not None
    assert 'list-products' in called['main']


def test_root_main_list_products_subprocess():
    """
    python main.py list-products из корня возвращает 0 и печатает продукты
    """
    r = subprocess.run(
        [sys.executable, str(ROOT / 'main.py'), 'list-products'],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert r.returncode == 0, r.stderr
    assert 'PostgreSQL' in r.stdout


def test_root_main_help_subprocess():
    """
    python main.py --help возвращает 0 и печатает справку
    """
    r = subprocess.run(
        [sys.executable, str(ROOT / 'main.py'), '--help'],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    assert 'safe-versions' in r.stdout
    assert 'vulns' in r.stdout


def test_root_main_unknown_command_subprocess():
    """
    python main.py unknown - argparse вернет ненулевой код
    """
    r = subprocess.run(
        [sys.executable, str(ROOT / 'main.py'), 'unknown-command'],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert r.returncode != 0


def test_root_main_no_args_starts_repl_subprocess():
    """
    python main.py без аргументов запускает REPL
    """
    r = subprocess.run(
        [sys.executable, str(ROOT / 'main.py')],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        input='exit\n',
        timeout=10,
    )
    assert r.returncode == 0, r.stderr
    assert 'Запуск в интерактивном режиме' in r.stdout


def test_root_main_repl_handles_command_subprocess():
    """
    В REPL через stdin передаем list-products, потом exit
    """
    r = subprocess.run(
        [sys.executable, str(ROOT / 'main.py')],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        input='list-products\nexit\n',
        timeout=10,
    )
    assert r.returncode == 0, r.stderr
    assert 'PostgreSQL' in r.stdout
