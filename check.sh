# Remove unused imports
ruff check --select F401 --fix src/

# Type-check
mypy src/main.py