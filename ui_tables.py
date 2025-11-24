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
# SECTION: AALERTS TABLE (top table)
# =============================================================================
# region AALERTS TABLE (top table)

def build_alerts_section(app, parent: "tk.Frame") -> None:
    """
    Build the Alerts section (filter row, legend, title, treeview + scrollbar)
    inside `parent`.

    Attaches the Treeview to `app.alerts` and the title var to `app.alerts_title`.
    """

    import tkinter as tk
    from tkinter import ttk

    # --- Filter row + legend ------------------------------------------------
    filter_row = ttk.Frame(parent)
    filter_row.pack(fill="x", pady=(4, 0))

    ttk.Label(filter_row, text="Filter (all tables):").pack(side="left")

    app.alert_filter_var = tk.StringVar()
    entry = ttk.Entry(filter_row, textvariable=app.alert_filter_var, width=30)
    entry.pack(side="left", padx=(4, 8))

    # live filtering as the user types (global across all tables)
    app.alert_filter_var.trace_add(
        "write", lambda *args: app._apply_alert_filter()
    )

    ttk.Button(
        filter_row,
        text="Clear",
        command=lambda: app.alert_filter_var.set(""),
    ).pack(side="left")

    # Legend for row highlight colours (right-aligned, next to details)
    legend = ttk.Frame(filter_row)
    legend.pack(side="right")

    def _legend_item(parent, color: str, text: str) -> None:
        swatch = tk.Label(
            parent,
            width=2,
            background=color,
            borderwidth=1,
            relief="solid",
        )
        swatch.pack(side="left", padx=(0, 2))
        ttk.Label(parent, text=text).pack(side="left", padx=(0, 8))

    # Colours come from main.py constants
    from ui_theme import (
        NEW_DEVICE_BACKGROUND,
        UNKNOWN_VENDOR_BACKGROUND,
        HIGH_VOLUME_BACKGROUND,
        STATUS_ICON_SIZE,
        COLOR_VENDOR_LABELLED,
        COLOR_VENDOR_KNOWN,
        COLOR_VENDOR_UNKNOWN,
    )
    
    '''
    NEW_DEVICE_BACKGROUND     = "#F7FFD2"
    UNKNOWN_VENDOR_BACKGROUND = "#FFECEC"
    HIGH_VOLUME_BACKGROUND    = "#D2F5FF"


    COLOR_VENDOR_LABELLED = "#00C000"
    COLOR_VENDOR_KNOWN    = "#0077FF"
    COLOR_VENDOR_UNKNOWN  = "#C00000"
    '''
    _legend_item(legend, NEW_DEVICE_BACKGROUND, "New device")
    _legend_item(legend, UNKNOWN_VENDOR_BACKGROUND, "Unknown / randomised")
    _legend_item(legend, HIGH_VOLUME_BACKGROUND, "High volume (≥ 1 MB)")

    # Status icon legend (same style as row highlights)
    _legend_item(legend, COLOR_VENDOR_LABELLED, "Labelled host")
    _legend_item(legend, COLOR_VENDOR_KNOWN , "Known vendor")
    _legend_item(legend, COLOR_VENDOR_UNKNOWN, "Unknown / randomised")
    


    # --- Alerts title -------------------------------------------------------
    app.alerts_title = tk.StringVar(value="Alerts")
    ttk.Label(
        parent,
        textvariable=app.alerts_title,
        anchor="w",
        font=("Segoe UI", 10, "bold"),
    ).pack(side="top", anchor="w", pady=(2, 0))

    # --- Treeview + scrollbar ----------------------------------------------
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

# ---------------------------------------------------------------------------
# REFRESH: ALERTS TABLE (top)
# ---------------------------------------------------------------------------

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
            local_hostport = alert.get("local", "")
            local_ip = local_hostport.rsplit(":", 1)[0] if ":" in local_hostport else ""
            mac_norm = normalize_mac(alert.get("mac", "") or "")
            vendor_disp = app._display_name(local_ip, mac_norm)

            # Destination: either "ip [hostname]:port" or "ip:port"
            remote_txt = alert.get("remote", "")
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
                    local_hostport,          # Local
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
# endregion AALERTS TABLE (top table)

# =============================================================================
# SECTION: ACTIVE CONNECTIONS TABLE (middle table)
# =============================================================================
# region ACTIVE CONNECTIONS TABLE (middle table)

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

    # #0 = status icon column
    app.tree.column("#0",      width=COL_W_STATUS, minwidth=20,  stretch=False, anchor="w")
    app.tree.column("first",   width=COL_W_FIRST,  minwidth=20,  stretch=False, anchor="w")
    app.tree.column("mac",     width=COL_W_MAC,    minwidth=20,  stretch=False, anchor="w")
    app.tree.column("vendor",  width=COL_W_VEND,   minwidth=20,  stretch=False, anchor="w")
    app.tree.column("dest",    width=COL_W_DEST,   minwidth=20,  stretch=True,  anchor="w")
    app.tree.column("local",   width=COL_W_LOCAL,  minwidth=20,  stretch=False, anchor="e")
    app.tree.column("last",    width=COL_W_LAST,   minwidth=20,  stretch=False, anchor="w")
    app.tree.column("bytes",   width=COL_W_BYTES,  minwidth=20,  stretch=False, anchor="e")
    app.tree.column("over1mb", width=70,           minwidth=20,  stretch=False, anchor="center")

    if DEBUG:
        app.tree.column("state", width=110, minwidth=80, stretch=False, anchor="center")

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

# ---------------------------------------------------------------------------
# REFRESH: ACTIVE CONNECTIONS TABLE (middle)
# ---------------------------------------------------------------------------

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
    core = app.core
    tree = app.tree

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

        # rDNS queuing
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

        dest_text = _fmt_dest(remote_ip, remote_port, dns_lock, dns_cache)
        local_hp = f'{rec["local_ip"]}:{rec["local_port"]}'
        mac_norm = normalize_mac(rec.get("local_mac") or "")
        vendor_disp = app._display_name(rec.get("local_ip"), mac_norm)

        bytes_val = int(rec.get("bytes_tx") or 0)
        vendor_text = vendor_disp or ""

        # "New" flow heuristic: first_seen == last_seen (just created session)
        is_new = rec.get("first_seen") == rec.get("last_seen")

        tags = _tags_for_row(vendor_text, bytes_val, is_new=is_new)
        status_img = app._status_icon_for_mac(mac_norm)

        row_vals = [
            rec.get("first_seen", ""),               # First Seen
            rec.get("local_mac", ""),                # MAC
            vendor_text,                             # Vendor/Host
            dest_text,                               # Destination
            local_hp,                                # Local
            rec.get("last_seen", ""),                # Last Seen
            bytes_val,                               # Bytes (TX)
            "Yes" if rec.get("over_1mb") else "No",  # >1MB?
        ]

        # Optional DEBUG state column
        from main import DEBUG  # if you still keep DEBUG there
        if DEBUG:
            row_vals.append(str(rec.get("state", "")).lower())

        tree.insert(
            "",
            "end",
            text="",          # status column text
            image=status_img, # coloured square
            values=tuple(row_vals),
            tags=tags,
        )

# endregion ACTIVE CONNECTIONS TABLE (middle table)

# =============================================================================
# SECTION: AGGREGATES TABLE (middle table) (bottom table)
# =============================================================================
# region: AGGREGATES TABLE (bottom table)

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

    # #0 = status icon
    app.agg.column("#0",        width=COL_W_STATUS, minwidth=20,  stretch=False, anchor="w")
    app.agg.column("sightings", width=COL_W_FIRST,  minwidth=20,  stretch=False, anchor="e")
    app.agg.column("mac",       width=COL_W_MAC,    minwidth=20,  stretch=False, anchor="w")
    app.agg.column("vendor",    width=COL_W_VEND,   minwidth=20,  stretch=False, anchor="w")
    app.agg.column("dest",      width=COL_W_DEST,   minwidth=20,  stretch=True,  anchor="w")
    app.agg.column("bytes",     width=COL_W_BYTES,  minwidth=20,  stretch=False, anchor="e")

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

# ---------------------------------------------------------------------------
# REFRESH: AGGREGATES TABLE (bottom)
# ---------------------------------------------------------------------------

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

    - Shows per-MAC destinations with total bytes and sightings
    - Applies row tags and status icons
    - Queues rDNS for aggregate destinations
    """
    core = app.core
    agg_tv = app.agg

    agg_tv.delete(*agg_tv.get_children())

    # 1) MACs discovered via ARP (devices present on LAN)
    macs_from_arp = {m for m in core.ip2mac.values() if m and m != "00:00:00:00:00:00"}

    # 2) MACs that we’ve accumulated traffic for
    macs_from_aggs = set(core.aggregates.keys())

    # 3) Union = all devices we know about
    all_macs = macs_from_arp | macs_from_aggs

    for mac in sorted(all_macs):
        mac_norm = normalize_mac(mac)
        vendor = app._display_name(ip=None, mac=mac_norm)
        dests = core.aggregates.get(mac, {})

        if not dests:
            # skip empty placeholders entirely
            continue

        for (rip, rport), stats in sorted(
            dests.items(),
            key=lambda kv: (-int(kv[1].get("bytes", 0)), kv[0]),
        ):
            # queue rDNS for aggregates as well
            if resolve_rdns and rip not in ("0.0.0.0", "127.0.0.1"):
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

            agg_dest = _fmt_dest(rip, rport, dns_lock, dns_cache)

            sightings = int(stats.get("sightings") or 0)
            bytes_val = int(stats.get("bytes") or 0)
            vendor_text = vendor or ""

            # Heuristic: a "new" device if we’ve only seen it a couple of times
            is_new = sightings <= 2

            tags = _tags_for_row(vendor_text, bytes_val, is_new=is_new)
            status_img = app._status_icon_for_mac(mac_norm)

            agg_tv.insert(
                "",
                "end",
                text="",
                image=status_img,
                values=(
                    sightings,     # Sightings
                    mac_norm,      # MAC (normalized)
                    vendor_text,   # Vendor/Host
                    agg_dest,      # Destination
                    bytes_val,     # Total Bytes
                ),
                tags=tags,
            )
# endregion AGGREGATES TABLE (bottom table)

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

    try:
        if int(bytes_val) >= 1_048_576:  # 1 MB threshold
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
