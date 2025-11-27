"""
ui_tables.py

Helpers to build the three main tables (Alerts, Active, Aggregates)
for the Dream Machine monitor UI.

We deliberately keep these functions "thin": they expect an `app`
instance that already has various helpers defined:
- app._setup_sorting(...)
- app._apply_saved_column_widths(...)
- app._bind_edit_on_doubleclick(...)
- app._update_details_from_tree(...)

They also attach Treeviews back onto `app` as:
- app.alerts
- app.tree     (active connections)
- app.agg      (aggregates)
"""

from __future__ import annotations
from typing import TYPE_CHECKING
from monitor_core import normalize_mac, _is_lan_client_ip

if TYPE_CHECKING:
    import tkinter as tk
    from tkinter import ttk
    from .main import App  # or adjust import path if needed

# Shared column width “defaults” – these mirror what you had in _build_ui
COL_W_FIRST = 140
COL_W_MAC   = 160
COL_W_VEND  = 220
COL_W_DEST  = 420
COL_W_LOCAL = 160
COL_W_LAST  = 140
COL_W_BYTES = 110
COL_W_STATUS = 32

def apply_default_alerts_column_widths(tv) -> None:
    """Apply built-in default column widths for the Alerts table."""
    tv.column("#0",     width=COL_W_STATUS, minwidth=20, stretch=False, anchor="w")
    tv.column("time",   width=COL_W_FIRST,  minwidth=20, stretch=False, anchor="w")
    tv.column("mac",    width=COL_W_MAC,    minwidth=20, stretch=False, anchor="w")
    tv.column("vendor", width=COL_W_VEND,   minwidth=20, stretch=False, anchor="w")
    tv.column("dest",   width=COL_W_DEST,   minwidth=20, stretch=True,  anchor="w")
    tv.column("local",  width=COL_W_LOCAL,  minwidth=20, stretch=False, anchor="e")
    tv.column("bytes",  width=COL_W_BYTES,  minwidth=20, stretch=False, anchor="e")
    tv.column("note",   width=180,          minwidth=20, stretch=False, anchor="w")


def apply_default_active_column_widths(tv, debug_enabled: bool) -> None:
    """Apply built-in default column widths for the Active Connections table."""
    tv.column("#0",      width=COL_W_STATUS, minwidth=20,  stretch=False, anchor="w")
    tv.column("first",   width=COL_W_FIRST,  minwidth=20,  stretch=False, anchor="w")
    tv.column("mac",     width=COL_W_MAC,    minwidth=20,  stretch=False, anchor="w")
    tv.column("vendor",  width=COL_W_VEND,   minwidth=20,  stretch=False, anchor="w")
    tv.column("dest",    width=COL_W_DEST,   minwidth=20,  stretch=True,  anchor="w")
    tv.column("local",   width=COL_W_LOCAL,  minwidth=20,  stretch=False, anchor="e")
    tv.column("last",    width=COL_W_LAST,   minwidth=20,  stretch=False, anchor="w")
    tv.column("bytes",   width=COL_W_BYTES,  minwidth=20,  stretch=False, anchor="e")
    tv.column("over1mb", width=70,           minwidth=20,  stretch=False, anchor="center")
    if debug_enabled:
        tv.column("state", width=110, minwidth=80, stretch=False, anchor="center")


def apply_default_aggregates_column_widths(tv) -> None:
    """Apply built-in default column widths for the Aggregates table."""
    tv.column("#0",        width=COL_W_STATUS, minwidth=20,  stretch=False, anchor="w")
    tv.column("sightings", width=COL_W_FIRST,  minwidth=20,  stretch=False, anchor="e")
    tv.column("mac",       width=COL_W_MAC,    minwidth=20,  stretch=False, anchor="w")
    tv.column("vendor",    width=COL_W_VEND,   minwidth=20,  stretch=False, anchor="w")
    tv.column("dest",      width=COL_W_DEST,   minwidth=20,  stretch=True,  anchor="w")
    tv.column("bytes",     width=COL_W_BYTES,  minwidth=20,  stretch=False, anchor="e")

def _force_headings(tv, labels: dict[str, str]) -> None:
    """
    Apply column IDs + headings WITHOUT overriding tv['show'].

    Some tables use 'tree headings' for a #0 status icon column,
    so we don’t touch tv['show'] here.
    """
    cols = tuple(labels.keys())
    tv["columns"] = cols
    tv["displaycolumns"] = cols
    for cid, txt in labels.items():
        tv.heading(cid, text=txt)

    def _reassert():
        for cid, txt in labels.items():
            tv.heading(cid, text=txt)

    tv.after_idle(_reassert)


# =============================================================================
# SECTION: BUILD AALERTS TABLE (top table)
# =============================================================================
# region BUILD AALERTS TABLE (top table)

def build_alerts_section(app, parent: "tk.Frame") -> None:
    """
    Build the Alerts section (filter rows, legend, title, treeview + scrollbar)
    inside `parent`.

    Attaches the Treeview to `app.alerts` and the title var to `app.alerts_title`.
    """

    import tkinter as tk
    from tkinter import ttk

     # =============================================================================
    # Filter rows + legend area
    # =============================================================================
    # region Filter row

    top = ttk.Frame(parent)
    top.pack(fill="x", pady=(4, 0))

    # Two horizontal rows
    top_row = ttk.Frame(top)
    top_row.pack(fill="x")
    bottom_row = ttk.Frame(top)
    bottom_row.pack(fill="x", pady=(2, 0))

    # Left side (filters)
    top_left = ttk.Frame(top_row)
    top_left.pack(side="left", fill="x", expand=True)
    bottom_left = ttk.Frame(bottom_row)
    bottom_left.pack(side="left", fill="x", expand=True)

    # Right side (legend rows)
    top_right = ttk.Frame(top_row)
    top_right.pack(side="right")
    bottom_right = ttk.Frame(bottom_row)
    bottom_right.pack(side="right")

    # --- Filter text (top-left row) ----------------------------------------
    ttk.Label(top_left, text="Filter (all tables):").pack(side="left")

    app.alert_filter_var = tk.StringVar()
    entry = ttk.Entry(top_left, textvariable=app.alert_filter_var, width=30)
    entry.pack(side="left", padx=(4, 8))

    # live filtering as the user types (global across all tables)
    app.alert_filter_var.trace_add(
        "write", lambda *args: app._apply_alert_filter()
    )

    ttk.Button(
        top_left,
        text="Clear",
        command=lambda: app.alert_filter_var.set(""),
    ).pack(side="left")

    # --- Persisted filter checkboxes (bottom-left row) ----------------------
    cfg = getattr(app, "cfg", {}) or {}

    hide_default = bool(cfg.get("filter_hide_web", False))
    only_unknown_default = bool(cfg.get("filter_only_unknown_laa", False))
    high_volume_default = bool(cfg.get("filter_high_volume_only", False))

    app.hide_web_var = getattr(
        app, "hide_web_var", tk.BooleanVar(value=hide_default)
    )
    app.only_unknown_laa_var = getattr(
        app, "only_unknown_laa_var", tk.BooleanVar(value=only_unknown_default)
    )
    app.high_volume_only_var = getattr(
        app, "high_volume_only_var", tk.BooleanVar(value=high_volume_default)
    )

    def _on_filter_toggle() -> None:
        """Persist filter checkboxes to config.json and refresh UI."""
        cfg_local = getattr(app, "cfg", None)
        if not isinstance(cfg_local, dict):
            return
        cfg_local.setdefault("column_widths", {})  # keep shape sane
        cfg_local["filter_hide_web"] = bool(app.hide_web_var.get())
        cfg_local["filter_only_unknown_laa"] = bool(app.only_unknown_laa_var.get())
        cfg_local["filter_high_volume_only"] = bool(app.high_volume_only_var.get())
        try:
            app.save_config()
        except Exception:
            pass

        # Rebuild the tables with the new filters
        if hasattr(app, "_refresh_ui"):
            app._refresh_ui()

    ttk.Checkbutton(
        bottom_left,
        text="Hide web (80/443)",
        variable=app.hide_web_var,
        command=_on_filter_toggle,
    ).pack(side="left", padx=(0, 8))

    ttk.Checkbutton(
        bottom_left,
        text="Only unknown/LAA",
        variable=app.only_unknown_laa_var,
        command=_on_filter_toggle,
    ).pack(side="left", padx=(0, 8))

    ttk.Checkbutton(
        bottom_left,
        text="High volume only (≥ 1 MB)",
        variable=app.high_volume_only_var,
        command=_on_filter_toggle,
    ).pack(side="left", padx=(0, 8))

    # endregion Filter row

    # =============================================================================
    # Legend block (two rows, aligned to the right of the filters)
    # =============================================================================
    # region Legend block (two rows, own area)

    # Colours come from ui_theme constants
    from ui_theme import (
        NEW_DEVICE_BACKGROUND,
        UNKNOWN_VENDOR_BACKGROUND,
        HIGH_VOLUME_BACKGROUND,
        STATUS_ICON_SIZE,           # not used here but kept imported if needed
        COLOR_VENDOR_LABELLED,
        COLOR_VENDOR_KNOWN,
        COLOR_VENDOR_UNKNOWN,
        COLOR_VENDOR_LAA,
    )

    # Top row: the row-highlight colours
    def make_legend_item(parent, color, text):
        f = ttk.Frame(parent)
        swatch = tk.Label(
            f,
            width=2,
            height=1,
            background=color,
            borderwidth=1,
            relief="solid",
        )
        swatch.pack(side="left", padx=(0, 4))
        ttk.Label(f, text=text).pack(side="left")
        return f

    # Top legend row – aligned with the search bar
    row1_items = [
        make_legend_item(top_right, NEW_DEVICE_BACKGROUND, "New device"),
        make_legend_item(top_right, UNKNOWN_VENDOR_BACKGROUND, "Unknown / randomised"),
        make_legend_item(top_right, HIGH_VOLUME_BACKGROUND, "High volume (≥ 1 MB)"),
        make_legend_item(top_right, COLOR_VENDOR_LABELLED, "Labelled host"),
    ]
    for col, item in enumerate(row1_items):
        item.grid(row=0, column=col, padx=4, pady=1, sticky="w")

    # Bottom legend row – aligned with the checkboxes
    row2_items = [
        make_legend_item(bottom_right, COLOR_VENDOR_KNOWN, "Known vendor"),
        make_legend_item(bottom_right, COLOR_VENDOR_LAA, "Randomised / LAA"),
        make_legend_item(bottom_right, COLOR_VENDOR_UNKNOWN, "Unknown vendor"),
    ]
    for col, item in enumerate(row2_items):
        item.grid(row=0, column=col, padx=4, pady=1, sticky="w")

    # region Legend block (two rows, own area)
    
    # =============================================================================
    # Alerts title
    # =============================================================================
    # region Alerts title

    app.alerts_title = tk.StringVar(value="Alerts")
    ttk.Label(
        parent,
        textvariable=app.alerts_title,
        anchor="w",
        font=("Segoe UI", 10, "bold"),
    ).pack(side="top", anchor="w", pady=(2, 0))
    
    # endregion Legend block (two rows, own area)
    
    # =============================================================================
    # SECTION: Treeview + scrollbar
    # =============================================================================
    # region Treeview + scrollbar

    alertf = ttk.Frame(parent)
    alertf.pack(fill="both", expand=True)

    alerts_labels = {
        "time":   "Time",
        "mac":    "MAC",
        "vendor": "Vendor/Host",
        "dest":   "Destination",
        "local":  "Local",
        "bytes":  "Bytes (TX)",
        "note":   "Note",
    }

    app.alerts = ttk.Treeview(
        alertf,
        columns=tuple(alerts_labels),
        show="tree headings",   # #0 = status icon
        height=8,
    )
    _force_headings(app.alerts, alerts_labels)

    # Clickable sorting
    app._setup_sorting(
        app.alerts,
        table_name="alerts",
        default_col="time",
        default_reverse=True,
    )

    # #0 = status icon column
    app.alerts.column("#0",     width=COL_W_STATUS, minwidth=20, stretch=False, anchor="w")
    app.alerts.column("time",   width=COL_W_FIRST,  minwidth=20, stretch=False, anchor="w")
    app.alerts.column("mac",    width=COL_W_MAC,    minwidth=20, stretch=False, anchor="w")
    app.alerts.column("vendor", width=COL_W_VEND,   minwidth=20, stretch=False, anchor="w")
    app.alerts.column("dest",   width=COL_W_DEST,   minwidth=20, stretch=True,  anchor="w")
    app.alerts.column("local",  width=COL_W_LOCAL,  minwidth=20, stretch=False, anchor="e")
    app.alerts.column("bytes",  width=COL_W_BYTES,  minwidth=20, stretch=False, anchor="e")
    app.alerts.column("note",   width=180,          minwidth=20, stretch=False, anchor="w")

    app._apply_saved_column_widths("alerts", app.alerts)

    # Row colour tags
    app.alerts.tag_configure("unknown_vendor", background=UNKNOWN_VENDOR_BACKGROUND)
    app.alerts.tag_configure("high_volume",    background=HIGH_VOLUME_BACKGROUND)
    app.alerts.tag_configure("new_device",     background=NEW_DEVICE_BACKGROUND)

    scry1 = ttk.Scrollbar(alertf, orient="vertical", command=app.alerts.yview)
    app.alerts.configure(yscrollcommand=scry1.set)
    app.alerts.pack(side="left", fill="both", expand=True, pady=8)
    scry1.pack(side="left", fill="y", padx=(0, 4), pady=8)

    # Edit-on-double-click
    if hasattr(app, "_bind_edit_on_doubleclick"):
        app._bind_edit_on_doubleclick(
            app.alerts,
            mac_col="mac",
            vendor_col="vendor",
            local_col="local",
        )

    app.alerts.bind("<Button-3>", app._on_right_click_active)
    app.alerts.bind(
        "<<TreeviewSelect>>",
        lambda e: app._update_details_from_tree(app.alerts, "alerts"),
    )

    # endregion Treeview + scrollbar
# endregion BUILD AALERTS TABLE (top table)

# =============================================================================
# SECTION: REFRESH: ALERTS TABLE (to tablep)
# =============================================================================
# region REFRESH: ALERTS TABLE (to tablep)

def refresh_alerts_table(app, *, toaster=None) -> None:
    """
    Drain core.alert_q and append rows to app.alerts.

    - Applies row tags via _tags_for_row
    - Uses app._status_icon_for_mac() for the status icon in #0
    - Trims the table to last 500 alerts
    - Optionally shows a Windows toast via `toaster`
    """
    import queue

    core = app.core
    alerts_tv = app.alerts

    try:
        while True:
            alert = core.alert_q.get_nowait()

            # Compute a vendor/label for the local endpoint’s MAC/IP
            local_hostport = alert.get("local", "") or ""
            local_ip = local_hostport.rsplit(":", 1)[0] if ":" in local_hostport else ""
            mac_norm = normalize_mac(alert.get("mac", "") or "")
            vendor_disp = app._display_name(local_ip, mac_norm)

            # Apply hostname aliases / rDNS to the "Local" column
            if hasattr(app, "_display_local"):
                local_display = app._display_local(local_hostport)
            else:
                local_display = local_hostport

            # Destination: either "ip [hostname]:port" or "ip:port"
            remote_txt = alert.get("remote", "") or ""
            if alert.get("hostname"):
                dest_text = f'{remote_txt} [{alert["hostname"]}]'
            else:
                dest_text = remote_txt

            bytes_val = int(alert.get("bytes", 0) or 0)
            vendor_text = vendor_disp or ""

            # Heuristic: "new device" if the note starts with that phrase
            is_new = str(alert.get("note", "")).lower().startswith("new device")

            tags = _tags_for_row(vendor_text, bytes_val, is_new=is_new)

            # Status icon in #0
            status_img = app._status_icon_for_mac(mac_norm)

            alerts_tv.insert(
                "",
                "end",
                image=status_img,  # first column (#0)
                values=(
                    alert.get("time", ""),   # Time
                    alert.get("mac", ""),    # MAC
                    vendor_text,             # Vendor/Host
                    dest_text,               # Destination
                    local_display,           # Local (with alias if known)
                    bytes_val,               # Bytes (TX)
                    alert.get("note", ""),   # Note
                ),
                tags=tags,
            )

            # Trim to last 500 alerts
            if len(alerts_tv.get_children()) > 500:
                for iid in alerts_tv.get_children()[:50]:
                    alerts_tv.delete(iid)

            # Optional Windows toast
            if toaster:
                try:
                    toaster.show_toast(
                        "Network Alert (>= 1 MB)",
                        f'{alert.get("local","")} → {alert.get("remote","")}\n'
                        f'{alert.get("vendor","")} {alert.get("mac","")}\n'
                        f'bytes={alert.get("bytes",0)}',
                        threaded=True,
                        duration=5,
                    )
                except Exception:
                    pass

    except queue.Empty:
        pass

    # After alerts table rebuilt: re-apply any filter text
    try:
        if hasattr(app, "alert_filter_var") and app.alert_filter_var.get():
            apply_filter = getattr(app, "_apply_alert_filter", None)
            if callable(apply_filter):
                apply_filter()
    except Exception:
        pass

# endregion REFRESH: ALERTS TABLE (to tablep)

# =============================================================================
# SECTION: BUILD ACTIVE CONNECTIONS TABLE (middle table)
# =============================================================================
# region BUILD ACTIVE CONNECTIONS TABLE (middle table)

def build_active_section(app, parent: "tk.Frame") -> None:
    """
    Build the Active Connections section inside `parent`.

    Attaches Treeview to app.tree and title var to app.active_title.
    """

    import tkinter as tk
    from tkinter import ttk

    app.active_title = tk.StringVar(value="Active Connections (top 200)")
    ttk.Label(
        parent,
        textvariable=app.active_title,
        anchor="w",
        font=("Segoe UI", 10, "bold"),
    ).pack(side="top", anchor="w", pady=(4, 0))

    midf = ttk.Frame(parent)
    midf.pack(fill="both", expand=True)

    active_labels = {
        "first":  "First Seen",
        "mac":    "MAC",
        "vendor": "Vendor/Host",
        "dest":   "Destination",
        "local":  "Local",
        "last":   "Last Seen",
        "bytes":  "Bytes (TX)",
        "over1mb":">1MB?",
    }

    from main import DEBUG

    if DEBUG:
        active_labels["state"] = "State"

    app.tree = ttk.Treeview(
        midf,
        columns=list(active_labels.keys()),
        show="tree headings",  # #0 = status icon
        height=10,
        selectmode="browse",
    )

    for col, label in active_labels.items():
        app.tree.heading(col, text=label, anchor="center")

    # Apply default widths via helper
    apply_default_active_column_widths(app.tree, DEBUG)

    # Sorting
    app._setup_sorting(app.tree, table_name="active", default_col="last", default_reverse=True)

    scry2 = ttk.Scrollbar(midf, orient="vertical", command=app.tree.yview)
    app.tree.configure(yscrollcommand=scry2.set)
    app.tree.pack(side="left", fill="both", expand=True, pady=8)
    scry2.pack(side="left", fill="y", padx=(0, 4), pady=8)

    # Edit-on-double-click
    if hasattr(app, "_bind_edit_on_doubleclick"):
        app._bind_edit_on_doubleclick(
            app.tree,
            mac_col="mac",
            vendor_col="vendor",
            local_col="local",
        )

    if hasattr(app, "_apply_state_visibility"):
        app._apply_state_visibility()

    app.tree.bind(
        "<<TreeviewSelect>>",
        lambda e: app._update_details_from_tree(app.tree, "active"),
    )

# endregion BUILD ACTIVE CONNECTIONS TABLE (middle table)

# =============================================================================
# SECTION: REFRESH: ACTIVE CONNECTIONS TABLE (middle table)
# =============================================================================
# region REFRESH: ACTIVE CONNECTIONS TABLE (middle table)

def refresh_active_table(
    app,
    *,
    dns_lock,
    dns_cache,
    dns_pending: set,
    resolve_rdns: bool,
) -> None:
    """
    Rebuild the Active Connections table (app.tree) from core.conn_map.

    - Filters out non-LAN, 0.0.0.0, and non-interesting states
    - Queues rDNS lookups via app._dns_q
    - Applies row tags and status icons
    """
    from main import ALERT_THRESHOLD_BYTES, DEBUG

    core = app.core
    tree = app.tree

    # Global filter toggles
    hide_web = bool(getattr(app, "hide_web_var", None) and app.hide_web_var.get())
    only_unknown_laa = bool(
        getattr(app, "only_unknown_laa_var", None)
        and app.only_unknown_laa_var.get()
    )
    high_volume_only = bool(
        getattr(app, "high_volume_only_var", None)
        and app.high_volume_only_var.get()
    )

    # Clear existing rows
    tree.delete(*tree.get_children())

    # Rebuild sorted by last_seen descending
    for key, rec in sorted(
        core.conn_map.items(),
        key=lambda kv: kv[1]["last_seen"],
        reverse=True,
    ):
        # Pre-filters (LAN, valid remote, state)
        if not _is_lan_client_ip(rec["local_ip"]):
            continue
        if rec["remote_ip"] == "0.0.0.0":
            continue
        if str(rec.get("state", "")).lower() in {"listen", "timewait", "closing"}:
            continue

        remote_ip = rec["remote_ip"]
        remote_port = rec["remote_port"]

        # Port-based filter: optionally hide common web ports
        try:
            port_int = int(remote_port)
        except Exception:
            port_int = None

        if hide_web and port_int in (80, 443, 8080, 8443):
            continue

        # rDNS queuing for remote endpoint
        if resolve_rdns and remote_ip not in ("0.0.0.0", "127.0.0.1"):
            with dns_lock:
                cached = dns_cache.get(remote_ip)
                pending = remote_ip in dns_pending
            if cached is None and not pending:
                with dns_lock:
                    dns_pending.add(remote_ip)
                try:
                    app._dns_q.put_nowait(remote_ip)
                except Exception:
                    pass

        # Destination column: ip [hostname]:port if we have rDNS, else ip:port
        dest_text = _fmt_dest(remote_ip, remote_port, dns_lock, dns_cache)

        local_hp = f'{rec["local_ip"]}:{rec["local_port"]}'

        # Apply hostname alias / rDNS to Local column
        if hasattr(app, "_display_local"):
            local_display = app._display_local(local_hp)
        else:
            local_display = local_hp

        mac_norm = normalize_mac(rec.get("local_mac") or "")
        vendor_disp = app._display_name(rec.get("local_ip"), mac_norm)

        # Status-level filter: only unknown/LAA devices if requested
        if only_unknown_laa:
            status_key = app._vendor_status_for_mac(mac_norm)
            if status_key not in ("unknown", "laa"):
                continue

        bytes_val = int(rec.get("bytes_tx") or 0)

        # Low-volume filter: drop rows below threshold when enabled
        if high_volume_only and bytes_val < ALERT_THRESHOLD_BYTES:
            continue

        vendor_text = vendor_disp or ""

        # "New" flow heuristic: first_seen == last_seen (just created session)
        is_new = rec.get("first_seen") == rec.get("last_seen")

        tags = _tags_for_row(vendor_text, bytes_val, is_new=is_new)
        status_img = app._status_icon_for_mac(mac_norm)

        over_1mb = bytes_val >= ALERT_THRESHOLD_BYTES

        row_vals = [
            rec.get("first_seen", ""),        # First Seen
            rec.get("local_mac", ""),         # MAC
            vendor_text,                      # Vendor/Host
            dest_text,                        # Destination (ip [hostname]:port)
            local_display,                    # Local (with alias if known)
            rec.get("last_seen", ""),         # Last Seen
            bytes_val,                        # Bytes (TX)
            "Yes" if over_1mb else "No",      # >1MB?
        ]

        # Optional DEBUG state column
        if DEBUG:
            row_vals.append(str(rec.get("state", "")).lower())

        tree.insert(
            "",
            "end",
            text="",          # status column text
            image=status_img, # coloured square
            values=row_vals,
            tags=tags,
        )


# endregion REFRESH: ACTIVE CONNECTIONS TABLE (middle table)

# =============================================================================
# SECTION: BUILD AGGREGATES TABLE (bottom table)
# =============================================================================
# region BUILD AGGREGATES TABLE (bottom table)

def build_aggregates_section(app, parent: "tk.Frame") -> None:
    """
    Build the Per-Device Totals (aggregates) section inside `parent`.

    Attaches Treeview to app.agg and title var to app.agg_title.
    """

    import tkinter as tk
    from tkinter import ttk

    app.agg_title = tk.StringVar(value="Per-Device Totals")
    ttk.Label(
        parent,
        textvariable=app.agg_title,
        anchor="w",
        font=("Segoe UI", 10, "bold"),
    ).pack(side="top", anchor="w", pady=(4, 0))

    aggf = ttk.Frame(parent)
    aggf.pack(fill="both", expand=True)

    agg_labels = {
        "sightings": "Sightings",
        "mac":       "MAC",
        "vendor":    "Vendor/Host",
        "dest":      "Destination",
        "bytes":     "Total Bytes",
    }

    app.agg = ttk.Treeview(
        aggf,
        columns=tuple(agg_labels),
        show="tree headings",   # #0 = status icon
        height=8,
    )
    _force_headings(app.agg, agg_labels)
    
    # Enable clickable sorting for Aggregates
    app._setup_sorting(
        app.agg,
        table_name="agg",
        default_col="bytes",      # default: largest first
        default_reverse=True,
    )

    from main import (
        NEW_DEVICE_BACKGROUND,
        UNKNOWN_VENDOR_BACKGROUND,
        HIGH_VOLUME_BACKGROUND,
    )

    # Apply default widths via helper
    apply_default_aggregates_column_widths(app.agg)

    # Row colour tags
    app.agg.tag_configure("unknown_vendor", background=UNKNOWN_VENDOR_BACKGROUND)
    app.agg.tag_configure("high_volume",    background=HIGH_VOLUME_BACKGROUND)
    app.agg.tag_configure("new_device",     background=NEW_DEVICE_BACKGROUND)

    scry3 = ttk.Scrollbar(aggf, orient="vertical", command=app.agg.yview)
    app.agg.configure(yscrollcommand=scry3.set)
    app.agg.pack(side="left", fill="both", expand=True, pady=8)
    scry3.pack(side="left", fill="y", padx=(0, 4), pady=8)

    if hasattr(app, "_bind_edit_on_doubleclick"):
        app._bind_edit_on_doubleclick(
            app.agg,
            mac_col="mac",
            vendor_col="vendor",
            local_col=None,
        )

    app.agg.bind("<Button-3>", app._on_right_click_active)
    app._apply_saved_column_widths("agg", app.agg)

    app.agg.bind(
        "<<TreeviewSelect>>",
        lambda e: app._update_details_from_tree(app.agg, "agg"),
    )

# endregion BUILD AGGREGATES TABLE (bottom table)

# =============================================================================
# SECTION: REFRESH: AGGREGATES TABLE (bottom table)
# =============================================================================
# region REFRESH: AGGREGATES TABLE (bottom table)

def refresh_aggregates_table(
    app,
    *,
    dns_lock,
    dns_cache,
    dns_pending: set,
    resolve_rdns: bool,
) -> None:
    """
    Rebuild the Aggregates table (app.agg) from core.aggregates + ARP cache.

    NEW BEHAVIOUR:
      - One row per MAC (device), not per (MAC, destination)
      - Sightings = total sightings across all destinations for that MAC
      - Bytes     = total bytes across all destinations for that MAC
      - Dest      = top-talkers summary:
                      "ip [hostname]:port" if single destination
                      "ip [hostname]:port (+N more)" if multiple
    """
    from main import ALERT_THRESHOLD_BYTES

    core = app.core
    agg_tv = app.agg

    hide_web = bool(getattr(app, "hide_web_var", None) and app.hide_web_var.get())
    only_unknown_laa = bool(
        getattr(app, "only_unknown_laa_var", None)
        and app.only_unknown_laa_var.get()
    )
    high_volume_only = bool(
        getattr(app, "high_volume_only_var", None)
        and app.high_volume_only_var.get()
    )

    # Clear existing rows
    agg_tv.delete(*agg_tv.get_children())

    # 1) MACs discovered via ARP (devices present on LAN)
    macs_from_arp = {m for m in core.ip2mac.values() if m and m != "00:00:00:00:00:00"}

    # 2) MACs that we’ve accumulated traffic for
    macs_from_aggs = set(core.aggregates.keys())

    # 3) Union = all devices we know about
    all_macs = macs_from_arp | macs_from_aggs

    WEB_PORTS = {80, 443, 8080, 8443}

    for mac in sorted(all_macs):
        mac_norm = normalize_mac(mac or "")
        if not mac_norm:
            continue

        dests = core.aggregates.get(mac, {})
        if not dests:
            # nothing to show for this MAC yet
            continue

        # =============================================================================
        # SECTION: Aggregate stats per MAC
        # =============================================================================
        # region Aggregate stats per MAC

        total_bytes = 0
        total_sightings = 0
        all_ports: set[int] = set()
        top_dest: tuple[str, str] | None = None
        top_bytes = -1

        for (rip, rport), stats in dests.items():
            try:
                b = int(stats.get("bytes") or 0)
            except Exception:
                b = 0
            try:
                s = int(stats.get("sightings") or 0)
            except Exception:
                s = 0

            total_bytes += b
            total_sightings += s

            try:
                port_int = int(rport)
            except Exception:
                port_int = None

            if port_int is not None:
                all_ports.add(port_int)

            if b > top_bytes:
                top_bytes = b
                top_dest = (rip, rport)

        if not total_sightings and not total_bytes:
            # truly empty / zero-ish device
            continue

        # endregion Aggregate stats per MAC
        
        # =============================================================================
        # SECTION: Filters
        # =============================================================================
        # region Filters

        # hide_web: skip devices whose *only* ports are common web ports
        if hide_web and all_ports and all(p in WEB_PORTS for p in all_ports):
            continue

        # Status-level filter: only unknown/LAA devices if requested
        if only_unknown_laa:
            status_key = app._vendor_status_for_mac(mac_norm)
            if status_key not in ("unknown", "laa"):
                continue

        # Low-volume filter: drop devices below threshold when enabled
        if high_volume_only and total_bytes < ALERT_THRESHOLD_BYTES:
            continue
        # endregion Filters

        # =============================================================================
        # SECTION: rDNS for the “top talker” destination
        # =============================================================================
        # region rDNS for the “top talker” destination

        if resolve_rdns and top_dest is not None:
            rip, _rport = top_dest
            if rip not in ("0.0.0.0", "127.0.0.1"):
                with dns_lock:
                    cached = dns_cache.get(rip)
                    pending = rip in dns_pending
                if cached is None and not pending:
                    with dns_lock:
                        dns_pending.add(rip)
                    try:
                        app._dns_q.put_nowait(rip)
                    except Exception:
                        pass
        # endregion rDNS for the “top talker” destination
        
        # =============================================================================
        # SECTION: Display strings
        # =============================================================================
        # region Display strings

        vendor_disp = app._display_name(local_ip=None, mac=mac_norm)
        vendor_text = vendor_disp or ""

        # Destination summary
        if top_dest is None:
            dest_text = ""
        else:
            rip, rport = top_dest
            dest_pretty = _fmt_dest(rip, rport, dns_lock, dns_cache)
            if len(dests) == 1:
                dest_text = dest_pretty
            else:
                dest_text = f"{dest_pretty} (+{len(dests) - 1} more)"

        # Heuristic: "new" device if only a couple of flows
        is_new = total_sightings <= 2

        tags = _tags_for_row(vendor_text, total_bytes, is_new=is_new)
        status_img = app._status_icon_for_mac(mac_norm)

        agg_tv.insert(
            "",
            "end",
            text="",
            image=status_img,
            values=(
                total_sightings,   # Sightings (sum over all dests)
                mac_norm,          # MAC (normalized)
                vendor_text,       # Vendor/Host
                dest_text,         # Top destination summary
                total_bytes,       # Total Bytes (all dests)
            ),
            tags=tags,
        )

        # endregion Display strings

# endregion REFRESH: AGGREGATES TABLE (bottom table)

# =============================================================================
# SECTION: SHARED HELPERS FOR REFRESH FUNCTIONS
# =============================================================================
# region: SHARED HELPERS FOR REFRESH FUNCTIONS

def _tags_for_row(vendor_text: str, bytes_val: int | float, *, is_new: bool = False) -> tuple[str, ...]:
    """
    Decide which tags to apply based on vendor / bytes / "newness".

    Tags:
      - unknown_vendor
      - high_volume
      - new_device
    """
    tags: list[str] = []

    v = (vendor_text or "").strip().lower()
    if not v or v == "unknown":
        tags.append("unknown_vendor")

    from main import ALERT_THRESHOLD_BYTES
    try:
        if int(bytes_val) >= ALERT_THRESHOLD_BYTES:  # 1 MB threshold
            tags.append("high_volume")
    except Exception:
        pass

    if is_new:
        tags.append("new_device")

    return tuple(tags)

def _fmt_dest(remote_ip: str, remote_port, dns_lock, dns_cache) -> str:
    """
    Format "ip[:port]" with cached rDNS if present.

    dns_lock / dns_cache are passed in from main.py so we don't import globals.
    """
    try:
        with dns_lock:
            host = dns_cache.get(remote_ip)
    except Exception:
        host = None
    return f"{remote_ip} [{host}]:{remote_port}" if host else f"{remote_ip}:{remote_port}"

# endregion SHARED HELPERS FOR REFRESH FUNCTIONS
