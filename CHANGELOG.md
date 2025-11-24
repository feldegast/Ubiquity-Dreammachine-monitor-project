## [6.0.0] – 2025-11-24

### Added
- Three-table layout split into dedicated helpers (`ui_tables.py`) for:
  - Alerts (top)
  - Active Connections (middle)
  - Per-Device Totals / Aggregates (bottom)
- Status-square icons in all three tables:
  - Icon column (#0) with small coloured squares per MAC quality.
- Column-width syncing for shared columns (`Time` / `First Seen`, `MAC`, `Vendor/Host`, etc.)
- JSON-based persistence of column widths in `config.json`.
- Legend/key for:
  - Row background meaning (new device, unknown vendor, high volume).
  - Status-square meaning (labelled / known / unknown vendor).

### Changed
- Refactored `_build_ui` to delegate table construction to `ui_tables.py` and keep `main.py` smaller and easier to edit.
- Refactored `_refresh_ui` so table refresh logic lives in `refresh_*_table` helpers in `ui_tables.py`.
- Aligned headings and column alignments between all three tables:
  - Common columns left-aligned where appropriate.
  - `Local` columns right-aligned for IP/port readability.
- Switched to image-based status icons with centralised colours and size in `ui_theme.py`.

### Fixed
- Sorting bugs in the Aggregates table (`bytes` and other numeric columns).
- Crashes relating to mixing `grid` and `pack` geometry managers in the same container.
- Various Pylance undefined-variable and min-width issues after the refactor.
