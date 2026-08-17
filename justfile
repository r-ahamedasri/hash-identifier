# justfile — task runner for hash-identifier
# run `just` with no args to list all recipes

# On Windows, run recipes through PowerShell instead of the (absent) `sh`.
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

default:
    @just --list

# create the venv and install the package + dev tools
setup:
    uv venv
    uv pip install -e ".[dev]"

# scan a single sample, e.g. `just scan 5f4dcc3b5aa765d61d8327deb882cf99`
scan sample:
    uv run hashid "{{sample}}"

# drop into interactive mode
shell:
    uv run hashid

# run the test suite
test:
    uv run pytest

# lint + type-check
check:
    uv run ruff check .
    uv run mypy src/

# auto-fix what ruff can fix
fix:
    uv run ruff check --fix .

# remove venv and caches (cross-platform)
clean:
    uv run python -c "import shutil, pathlib; [shutil.rmtree(p, ignore_errors=True) for p in ['.venv', '.pytest_cache', 'dist', 'build'] + [str(p) for p in pathlib.Path('.').rglob('__pycache__')] + [str(p) for p in pathlib.Path('.').glob('*.egg-info')]]"