#!/usr/bin/env python3
import curses
import psutil
import time
import os
import logging
from datetime import datetime
import subprocess
import sys
import argparse
import re
import tomllib
import signal
import sqlite3
import smtplib
from email.mime.text import MIMEText
import urllib.request
import json
import socket
from collections import deque
from typing import List, Dict, Optional, Tuple, Any

# =========================
# Theming constants/paths
# =========================
THEME_DIR = "/etc/swapwatch/themes"
DEFAULT_THEME_NAME = "tokyonight.theme"  # will try to use if present
DEFAULT_CONFIG_PATH = "/etc/swapwatch/config.toml"

# Supported base colors map (standard curses 8-color palette)
COLOR_NAME_MAP = {
    "black": curses.COLOR_BLACK,
    "red": curses.COLOR_RED,
    "green": curses.COLOR_GREEN,
    "yellow": curses.COLOR_YELLOW,
    "blue": curses.COLOR_BLUE,
    "magenta": curses.COLOR_MAGENTA,
    "cyan": curses.COLOR_CYAN,
    "white": curses.COLOR_WHITE,
}

# Logical roles we colorize
THEME_ROLES = [
    "background_fg", "background_bg",
    "title_fg", "title_bg",
    "border_fg",
    "timestamp_fg",
    "swap_label_fg",
    "percent_ok_fg", "percent_high_fg",
    "mem_label_fg",
    "log_text_fg",
    "menu_text_fg",
    "menu_hl_fg", "menu_hl_bg",
    "statusbar_fg", "statusbar_bg",
]

# Default theme values (safe fallback)
DEFAULT_THEME_VALUES = {
    "background_fg": "white",
    "background_bg": "black",

    "title_fg": "cyan",
    "title_bg": "black",
    "border_fg": "blue",
    "timestamp_fg": "yellow",
    "swap_label_fg": "magenta",
    "percent_ok_fg": "green",
    "percent_high_fg": "red",
    "mem_label_fg": "cyan",
    "log_text_fg": "white",
    "menu_text_fg": "white",
    "menu_hl_fg": "black",
    "menu_hl_bg": "yellow",
    "statusbar_fg": "black",
    "statusbar_bg": "cyan",
}

# Pair registry (will be filled at runtime): role -> pair_id
COLOR_PAIRS = {}
# Flags
COLORS_ENABLED = False
COLORS_256 = False

# Logging setup
LOG_FILE = "/var/log/swapwatch.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',  # Logging module adds timestamp
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ============== OSC 11 TRUECOLOR BACKGROUND SUPPORT ==============
CSI = "\x1b["
OSC = "\x1b]"
BEL = "\x07"

def _rgb_to_hex(r: int, g: int, b: int) -> str:
    """Convert RGB values to a hex color string."""
    return f"#{r:02x}{g:02x}{b:02x}"

def _x256_to_rgb(n: int) -> Tuple[int, int, int]:
    """Convert xterm-256 color index to RGB tuple."""
    n = max(0, min(255, int(n)))
    if 16 <= n <= 231:
        n -= 16
        r = (n // 36) % 6
        g = (n // 6) % 6
        b = n % 6
        table = [0, 95, 135, 175, 215, 255]
        return (table[r], table[g], table[b])
    if 232 <= n <= 255:
        g = 8 + (n - 232) * 10
        return (g, g, g)
    basic = {
        0:(0,0,0), 1:(205,0,0), 2:(0,205,0), 3:(205,205,0),
        4:(0,0,238), 5:(205,0,205), 6:(0,205,205), 7:(229,229,229),
        8:(127,127,127), 9:(255,0,0), 10:(0,255,0), 11:(255,255,0),
        12:(92,92,255), 13:(255,0,255), 14:(0,255,255), 15:(255,255,255)
    }
    return basic.get(n, (0,0,0))

def _named_to_rgb(name: str) -> Tuple[int, int, int]:
    """Convert a named color to an RGB tuple."""
    m = {
        "black":(0,0,0),"red":(255,0,0),"green":(0,255,0),"yellow":(255,255,0),
        "blue":(0,0,255),"magenta":(255,0,255),"cyan":(0,255,255),"white":(255,255,255)
    }
    return m.get(name.lower(), (0,0,0))

def value_to_hex(v: str) -> str:
    """Convert a theme color value (name, x256:N, or #RRGGBB) to hex string."""
    if not v: return "#000000"
    v = v.strip().lower()
    if v.startswith("#") and len(v) == 7:
        return v
    if v.startswith("x256:"):
        try:
            n = int(v.split(":",1)[1])
        except Exception:
            n = 0
        r,g,b = _x256_to_rgb(n)
        return _rgb_to_hex(r,g,b)
    if v in COLOR_NAME_MAP:
        r,g,b = _named_to_rgb(v)
        return _rgb_to_hex(r,g,b)
    return "#000000"

def osc11_set_bg(hex_rgb: str) -> None:
    """Set terminal default background to hex (#RRGGBB) using OSC 11."""
    try:
        os.write(sys.stdout.fileno(), (f"{OSC}11;{hex_rgb}{BEL}").encode("utf-8"))
    except Exception:
        pass
# ================================================================


def apply_prlimit(pid: int, mem_limit_bytes: int) -> bool:
    """Apply virtual memory limit to a process."""
    try:
        subprocess.run(["prlimit", "--pid", str(pid), "--as=" + str(mem_limit_bytes)], check=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.warning(f"Failed to apply prlimit to PID {pid}: {e}")
        return False


# Monitored applications mapping: process names to service names and include_children flag
# Specify which apps should include child processes
monitored_apps = {
    # process_name: (service_name, include_children)
    "clamd": ("clamav-daemon", False),
    "spamd": ("spamd", False),
    "dovecot": ("dovecot", False),
    "opendmarc": ("opendmarc", False),
    "opendkim": ("opendkim", False),
    "vsftpd": ("vsftpd", False),
    "kiwiirc": ("kiwiirc", False),
    "amavisd": ("amavis", True),
    "postfix": ("postfix", False),
    "fail2ban": ("fail2ban", False),
    "webmin": ("webmin", False),
    "monitorix": ("monitorix", False),
    "php-fpm8.2": ("php8.2-fpm", False),
    "php-fpm8.3": ("php8.3-fpm", False),
    "mariadbd": ("mariadb", False),
    "vnstat": ("vnstat", False),
    "nginx": ("nginx", True)  # Include nginx and combine child processes
}

# Default swap thresholds (can be overridden via command-line arguments)
SWAP_HIGH_THRESHOLD = 80  # Threshold to start taking action
SWAP_LOW_THRESHOLD = 65   # Target swap usage to achieve

# Check interval in seconds (5 minutes)
CHECK_INTERVAL = 300

# UI update interval in seconds
UI_UPDATE_INTERVAL = 3  # Update UI every 3 seconds for better efficiency

# Performance optimization globals
_cached_monitored_pids = {}
_cached_swap_data = []
_last_pid_scan = 0
_last_swap_scan = 0
_performance_stats = {
    'process_scans': 0,
    'file_reads': 0,
    'cache_hits': 0,
    'last_scan_duration': 0.0,
    'adaptive_cache_time': 10  # Dynamic cache time that adapts to system load
}

# Log display state (updated when UI is set up)
log_lines_visible = 0
MAX_LOG_LINES = 1000

# Signal handling
_shutdown_requested = False

# Swap history for sparkline
_swap_history: deque = deque(maxlen=60)
SPARKLINE_CHARS = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"

# Search state
_in_search = False
_search_query = ""
_search_matches: List[int] = []
_search_match_idx = -1

# App-select state (for process detail view)
_in_app_select = False
_app_select_idx = 0


# =========================
# Configuration System
# =========================
def load_config(config_path: str) -> dict:
    """Load TOML config file, returning a dict. Returns empty dict if file missing."""
    if not os.path.isfile(config_path):
        return {}
    try:
        with open(config_path, "rb") as f:
            return tomllib.load(f)
    except Exception as e:
        logging.warning(f"Failed to load config from {config_path}: {e}")
        return {}


def apply_config(config: dict) -> None:
    """Apply loaded config dict to global constants. Called once at startup."""
    global LOG_FILE, THEME_DIR, DEFAULT_THEME_NAME
    global SWAP_HIGH_THRESHOLD, SWAP_LOW_THRESHOLD
    global CHECK_INTERVAL, UI_UPDATE_INTERVAL, MAX_LOG_LINES
    global monitored_apps, _performance_stats

    general = config.get("general", {})
    if "log_file" in general:
        LOG_FILE = general["log_file"]
    if "check_interval" in general:
        CHECK_INTERVAL = general["check_interval"]
    if "ui_update_interval" in general:
        UI_UPDATE_INTERVAL = general["ui_update_interval"]
    if "max_log_lines" in general:
        MAX_LOG_LINES = general["max_log_lines"]

    thresholds = config.get("thresholds", {})
    if "swap_high" in thresholds:
        SWAP_HIGH_THRESHOLD = thresholds["swap_high"]
    if "swap_low" in thresholds:
        SWAP_LOW_THRESHOLD = thresholds["swap_low"]

    theme_cfg = config.get("theme", {})
    if "theme_dir" in theme_cfg:
        THEME_DIR = theme_cfg["theme_dir"]
    if "default_theme" in theme_cfg:
        DEFAULT_THEME_NAME = theme_cfg["default_theme"]

    perf = config.get("performance", {})
    if "adaptive_cache_min" in perf:
        _performance_stats['adaptive_cache_time'] = perf["adaptive_cache_min"]
        _performance_stats['adaptive_cache_min'] = perf["adaptive_cache_min"]
    if "adaptive_cache_max" in perf:
        _performance_stats['adaptive_cache_max'] = perf["adaptive_cache_max"]

    # Override monitored_apps from config if section exists
    apps_cfg = config.get("monitored_apps", {})
    if apps_cfg:
        monitored_apps.clear()
        for proc_name, app_info in apps_cfg.items():
            service = app_info.get("service_name", proc_name)
            children = app_info.get("include_children", False)
            monitored_apps[proc_name] = (service, children)


def _signal_handler(signum: int, frame: Any) -> None:
    """Handle SIGTERM/SIGINT by setting shutdown flag."""
    global _shutdown_requested
    _shutdown_requested = True


# =========================
# Alerting System
# =========================
class AlertManager:
    """Manages email and webhook alerts with cooldown to prevent spam."""

    def __init__(self, config: dict) -> None:
        alerts_cfg = config.get("alerts", {})
        self.enabled = alerts_cfg.get("enabled", False)
        self.cooldown_seconds = alerts_cfg.get("cooldown_minutes", 15) * 60
        self._last_sent: Dict[str, float] = {}

        email_cfg = alerts_cfg.get("email", {})
        self.email_enabled = email_cfg.get("enabled", False)
        self.email_to = email_cfg.get("to", "")
        self.email_from = email_cfg.get("from_addr", "swapwatch@localhost")
        self.smtp_host = email_cfg.get("smtp_host", "localhost")
        self.smtp_port = email_cfg.get("smtp_port", 25)

        webhook_cfg = alerts_cfg.get("webhook", {})
        self.webhook_enabled = webhook_cfg.get("enabled", False)
        self.webhook_url = webhook_cfg.get("url", "")

    def _is_cooled_down(self, alert_key: str) -> bool:
        last = self._last_sent.get(alert_key, 0)
        return (time.time() - last) >= self.cooldown_seconds

    def send_alert(self, severity: str, message: str, swap_percent: float) -> None:
        """Send alert via configured channels if cooldown has elapsed."""
        if not self.enabled:
            return
        alert_key = f"{severity}:{message[:50]}"
        if not self._is_cooled_down(alert_key):
            return
        self._last_sent[alert_key] = time.time()

        hostname = socket.gethostname()
        timestamp = datetime.now().isoformat()

        if self.email_enabled and self.email_to:
            self._send_email(severity, message, swap_percent, hostname, timestamp)
        if self.webhook_enabled and self.webhook_url:
            self._send_webhook(severity, message, swap_percent, hostname, timestamp)

    def _send_email(self, severity: str, message: str, swap_percent: float,
                    hostname: str, timestamp: str) -> None:
        try:
            body = (
                f"SwapWatch Alert [{severity.upper()}]\n"
                f"Host: {hostname}\n"
                f"Time: {timestamp}\n"
                f"Swap: {swap_percent:.1f}%\n"
                f"Message: {message}\n"
            )
            msg = MIMEText(body)
            msg["Subject"] = f"[SwapWatch] {severity.upper()}: {message[:80]}"
            msg["From"] = self.email_from
            msg["To"] = self.email_to
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                server.send_message(msg)
        except Exception as e:
            logging.warning(f"Alert email failed: {e}")

    def _send_webhook(self, severity: str, message: str, swap_percent: float,
                      hostname: str, timestamp: str) -> None:
        try:
            payload = json.dumps({
                "severity": severity,
                "message": message,
                "swap_percent": swap_percent,
                "timestamp": timestamp,
                "hostname": hostname,
            }).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url, data=payload,
                headers={"Content-Type": "application/json"}, method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            logging.warning(f"Alert webhook failed: {e}")


# =========================
# Historical Metrics (SQLite)
# =========================
class MetricsDB:
    """SQLite-based historical metrics storage."""

    def __init__(self, config: dict) -> None:
        history_cfg = config.get("history", {})
        self.enabled = history_cfg.get("enabled", False)
        self.db_path = history_cfg.get("db_path", "/var/lib/swapwatch/metrics.db")
        self.retention_days = history_cfg.get("retention_days", 30)
        self.sample_interval = history_cfg.get("sample_interval", 300)
        self._conn: Optional[sqlite3.Connection] = None
        self._last_sample_time: float = 0

        if self.enabled:
            self._init_db()

    def _init_db(self) -> None:
        try:
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.isdir(db_dir):
                os.makedirs(db_dir, mode=0o755, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, timeout=5)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS swap_samples (
                    timestamp TEXT NOT NULL,
                    swap_percent REAL NOT NULL,
                    mem_percent REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS app_swap_usage (
                    timestamp TEXT NOT NULL,
                    app_name TEXT NOT NULL,
                    swap_bytes INTEGER NOT NULL,
                    swap_percent REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS actions_log (
                    timestamp TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT,
                    result TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_swap_ts ON swap_samples(timestamp);
                CREATE INDEX IF NOT EXISTS idx_app_ts ON app_swap_usage(timestamp);
                CREATE INDEX IF NOT EXISTS idx_actions_ts ON actions_log(timestamp);
            """)
            self._conn.commit()
            self._cleanup_old_records()
        except Exception as e:
            logging.warning(f"MetricsDB init failed: {e}")
            self.enabled = False
            self._conn = None

    def _cleanup_old_records(self) -> None:
        if not self._conn:
            return
        try:
            cutoff = datetime.now().timestamp() - (self.retention_days * 86400)
            cutoff_str = datetime.fromtimestamp(cutoff).isoformat()
            self._conn.execute("DELETE FROM swap_samples WHERE timestamp < ?", (cutoff_str,))
            self._conn.execute("DELETE FROM app_swap_usage WHERE timestamp < ?", (cutoff_str,))
            self._conn.execute("DELETE FROM actions_log WHERE timestamp < ?", (cutoff_str,))
            self._conn.commit()
        except Exception as e:
            logging.warning(f"MetricsDB cleanup failed: {e}")

    def record_sample(self, swap_percent: float, mem_percent: float,
                      app_data: Optional[List[dict]] = None) -> None:
        """Record a swap/memory sample if enough time has elapsed."""
        if not self.enabled or not self._conn:
            return
        now = time.time()
        if now - self._last_sample_time < self.sample_interval:
            return
        self._last_sample_time = now
        ts = datetime.now().isoformat()
        try:
            self._conn.execute(
                "INSERT INTO swap_samples (timestamp, swap_percent, mem_percent) VALUES (?, ?, ?)",
                (ts, swap_percent, mem_percent)
            )
            if app_data:
                for app in app_data:
                    self._conn.execute(
                        "INSERT INTO app_swap_usage (timestamp, app_name, swap_bytes, swap_percent) VALUES (?, ?, ?, ?)",
                        (ts, app['name'], app['swap_bytes'], app['swap_percent'])
                    )
            self._conn.commit()
        except Exception as e:
            logging.warning(f"MetricsDB record failed: {e}")

    def record_action(self, action_type: str, target: str, result: str) -> None:
        """Record a service action (restart, etc.)."""
        if not self.enabled or not self._conn:
            return
        ts = datetime.now().isoformat()
        try:
            self._conn.execute(
                "INSERT INTO actions_log (timestamp, action_type, target, result) VALUES (?, ?, ?, ?)",
                (ts, action_type, target, result)
            )
            self._conn.commit()
        except Exception as e:
            logging.warning(f"MetricsDB action log failed: {e}")

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass


# Help text for command-line arguments
CMD_HELP_TEXT = """
SwapWatch Command-Line Options:
-------------------------------

Usage:
  swapwatch.py [options]

Options:
  -h, --help            Show this help message and exit.
  --swap-high VALUE     Set the swap high threshold percentage (default: 75).
  --swap-low VALUE      Set the swap low threshold percentage (default: 50).

Example:
  swapwatch.py --swap-high 80 --swap-low 60
"""

# Help text for the application (displayed with '?')
APP_HELP_TEXT = """
SwapWatch 2.0 Help Menu
------------------------

Available Commands:
- 'q'       : Quit the application.
- 'm'       : Open the menu to select and restart monitored applications.
- 't'       : Open theme selector and apply a theme.
- '?'       : Display this help menu.
- Up/Down   : Scroll through logs or navigate menus.
- 'r'       : Restart selected service in the menu.
- 'c'       : Force cache refresh for immediate data update.
- 'Esc'     : Exit from the menu/help/theme screen.

Features:
- Real-time monitoring of swap usage (not just memory!).
- Smart caching system for 80%+ better performance.
- Top 10 swap-using applications display with auto-scroll.
- VPS-optimized with intelligent cache clearing detection.
- Targets highest swap users for restart decisions.
- Performance statistics display showing cache efficiency.
- Themeable UI loaded from /etc/swapwatch/themes/*.theme

Performance Optimizations (v2.0):
- PID caching reduces process scans by 90%
- Batch /proc file reading minimizes I/O operations
- Smart refresh intervals adapt to data change frequency
- Cache hit rates typically >85% after initial scan
"""

# -------------
# THEME SYSTEM
# -------------
def ensure_theme_dir() -> bool:
    """Check if the theme directory exists."""
    return os.path.isdir(THEME_DIR)


def list_theme_files() -> List[str]:
    """Return sorted list of .theme filenames from the theme directory."""
    if not ensure_theme_dir():
        return []
    files = []
    try:
        for name in os.listdir(THEME_DIR):
            if name.endswith(".theme") and os.path.isfile(os.path.join(THEME_DIR, name)):
                files.append(name)
    except Exception:
        pass
    files.sort()
    return files


def _hex_to_256(hexstr: str) -> Optional[int]:
    """Map #RRGGBB to nearest xterm-256 color index (approx using color cube)."""
    if hexstr.startswith("#"):
        hexstr = hexstr[1:]
    if len(hexstr) != 6:
        return None
    try:
        r = int(hexstr[0:2], 16)
        g = int(hexstr[2:4], 16)
        b = int(hexstr[4:6], 16)
    except ValueError:
        return None

    def to_cube(v):
        if v < 48:
            return 0
        if v < 114:
            return 1
        return (v - 35) // 40

    rc, gc, bc = int(to_cube(r)), int(to_cube(g)), int(to_cube(b))
    idx = 16 + 36 * rc + 6 * gc + bc
    if abs(r - g) < 10 and abs(g - b) < 10:
        gray = int(round((r + g + b) / 3.0))
        gidx = 232 + int((gray * 23) / 255)
        return gidx
    return idx


def parse_theme_file(path: str) -> Dict[str, str]:
    """Parse a .theme file into a dict of role->color value.

    Supports named colors, x256:<index>, and #RRGGBB hex values.
    """
    theme = DEFAULT_THEME_VALUES.copy()
    try:
        with open(path, "r") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, val = [p.strip() for p in line.split("=", 1)]
                k = key.lower()
                v = val.lower()
                if k in THEME_ROLES:
                    theme[k] = v
    except Exception:
        pass
    return theme


def get_color_number(value: str) -> int:
    """Return a curses color number from a theme color value."""
    if value in COLOR_NAME_MAP:
        return COLOR_NAME_MAP[value]
    if value.startswith("x256:"):
        try:
            n = int(value.split(":", 1)[1])
            if 0 <= n <= 255 and COLORS_256:
                return n
            return COLOR_NAME_MAP.get("white", curses.COLOR_WHITE)
        except ValueError:
            return COLOR_NAME_MAP.get("white", curses.COLOR_WHITE)
    if value.startswith("#"):
        idx = _hex_to_256(value)
        if idx is not None and COLORS_256:
            return idx
        return COLOR_NAME_MAP.get("white", curses.COLOR_WHITE)
    return COLOR_NAME_MAP.get("white", curses.COLOR_WHITE)


def color_attr_for(role: str) -> int:
    """Return curses attribute (color pair) for a role, or 0 if colors disabled."""
    if COLORS_ENABLED and role in COLOR_PAIRS:
        return curses.color_pair(COLOR_PAIRS[role])
    return 0


def init_color_pairs(theme_values: Dict[str, str]) -> None:
    """Register curses color pairs for all theme roles."""
    global COLOR_PAIRS
    COLOR_PAIRS.clear()
    pair_id = 1

    def mkpair(role, fg_key, bg_key=None, force_bg=False):
        nonlocal pair_id
        fg_num = get_color_number(theme_values.get(fg_key, "white"))
        if force_bg and bg_key:
            bg_num = get_color_number(theme_values.get(bg_key, "black"))
        else:
            # inherit terminal default background (truecolor from OSC 11)
            bg_num = -1
        try:
            curses.init_pair(pair_id, fg_num, bg_num)
        except curses.error:
            curses.init_pair(pair_id, COLOR_NAME_MAP["white"], -1)
        COLOR_PAIRS[role] = pair_id
        pair_id += 1

    # Background (text on default bg)
    mkpair("background", "background_fg", "background_bg", force_bg=False)

    # Title (text on default bg)
    mkpair("title", "title_fg", "title_bg", force_bg=False)
    # Borders (fg only)
    mkpair("border", "border_fg", "background_bg", force_bg=False)
    # Timestamp
    mkpair("timestamp", "timestamp_fg", "background_bg", force_bg=False)
    # Labels
    mkpair("swap_label", "swap_label_fg", "background_bg", force_bg=False)
    mkpair("mem_label", "mem_label_fg", "background_bg", force_bg=False)
    # Percentages
    mkpair("percent_ok", "percent_ok_fg", "background_bg", force_bg=False)
    mkpair("percent_high", "percent_high_fg", "background_bg", force_bg=False)
    # Log text
    mkpair("log_text", "log_text_fg", "background_bg", force_bg=False)
    # Menu text
    mkpair("menu_text", "menu_text_fg", "background_bg", force_bg=False)
    # Menu highlight (explicit bg so selection stands out)
    mkpair("menu_hl", "menu_hl_fg", "menu_hl_bg", force_bg=True)
    # Status bar (explicit bg so it stands out)
    mkpair("statusbar", "statusbar_fg", "statusbar_bg", force_bg=True)


def apply_theme(theme_values: Dict[str, str]) -> None:
    """Apply theme values to curses color pairs (if colors enabled) and OSC bg."""
    # Set terminal default background to truecolor (OSC 11) from theme bg
    hex_bg = value_to_hex(theme_values.get("background_bg", "black"))
    osc11_set_bg(hex_bg)
    if COLORS_ENABLED:
        init_color_pairs(theme_values)


def load_theme_by_name(theme_name: str) -> Dict[str, str]:
    """Load and apply a theme from THEME_DIR by name."""
    path = os.path.join(THEME_DIR, theme_name)
    theme = parse_theme_file(path)
    apply_theme(theme)
    return theme


# Initialize curses
def init_curses() -> 'curses.window':
    """Initialize curses mode with colors and non-blocking input."""
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    curses.curs_set(0)  # Hide the cursor
    stdscr.nodelay(True)  # Make getch non-blocking

    global COLORS_ENABLED, COLORS_256
    COLORS_ENABLED = False
    COLORS_256 = False
    try:
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()  # enable -1 (terminal default bg)
            except curses.error:
                pass
            COLORS_ENABLED = True
            try:
                COLORS_256 = (curses.COLORS >= 256)
            except Exception:
                COLORS_256 = False
    except Exception:
        COLORS_ENABLED = False
    return stdscr


# Close curses
def close_curses(stdscr: 'curses.window') -> None:
    """Restore terminal state and exit curses mode."""
    try:
        os.write(sys.stdout.fileno(), b"\x1b]111\x07")
    except Exception:
        pass
    curses.nocbreak()
    stdscr.keypad(False)
    curses.echo()
    curses.endwin()


# Get memory and swap usage
def get_memory_and_swap_usage() -> Tuple[float, float]:
    """Return (memory_percent, swap_percent) as a tuple."""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return mem.percent, swap.percent


# Restart app
def restart_app(service_name: str, log_lines: List[str], log_scroll_pos: int,
                 metrics_db: Optional['MetricsDB'] = None) -> int:
    """Restart a systemd service and log the result.

    Returns:
        Updated log scroll position.
    """
    try:
        log_scroll_pos = log_action(f"Restarting service {service_name}", log_lines, log_scroll_pos)
        subprocess.run(
            ['systemctl', 'restart', service_name],
            check=True,
            timeout=60,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        log_scroll_pos = log_action(f"Service {service_name} restarted successfully.", log_lines, log_scroll_pos)
        if metrics_db:
            metrics_db.record_action("restart", service_name, "success")
    except subprocess.TimeoutExpired:
        log_scroll_pos = log_action(f"Restarting {service_name} timed out.", log_lines, log_scroll_pos)
        if metrics_db:
            metrics_db.record_action("restart", service_name, "timeout")
    except subprocess.CalledProcessError as e:
        log_scroll_pos = log_action(f"Failed to restart {service_name}: {e.stderr.strip()}", log_lines, log_scroll_pos)
        if metrics_db:
            metrics_db.record_action("restart", service_name, f"failed: {e.stderr.strip()}")
    except Exception as e:
        log_scroll_pos = log_action(f"Unexpected error restarting {service_name}: {e}", log_lines, log_scroll_pos)
        if metrics_db:
            metrics_db.record_action("restart", service_name, f"error: {e}")
    return log_scroll_pos


# Drop caches
def drop_caches(log_lines: List[str], log_scroll_pos: int) -> int:
    """Sync and drop kernel caches, logging any freed memory.

    Returns:
        Updated log scroll position.
    """
    try:
        # Get memory stats before clearing
        mem_before = psutil.virtual_memory()
        swap_before = psutil.swap_memory()

        # Try to sync and drop caches
        subprocess.run(['sync'], check=True)
        with open('/proc/sys/vm/drop_caches', 'w') as f:
            f.write('3\n')

        # Wait a moment for the operation to complete
        time.sleep(1)

        # Get memory stats after clearing
        mem_after = psutil.virtual_memory()
        swap_after = psutil.swap_memory()

        # Check if cache clearing actually had an effect
        mem_freed = mem_before.used - mem_after.used
        swap_freed = swap_before.used - swap_after.used

        if mem_freed > 0 or swap_freed > 0:
            freed_mb = mem_freed / (1024 * 1024)
            swap_freed_mb = swap_freed / (1024 * 1024)
            if freed_mb > 1 or swap_freed_mb > 1:  # Only log if meaningful amount freed
                if swap_freed_mb > 1:
                    log_scroll_pos = log_action(f"Cleared caches: freed {freed_mb:.1f}MB memory, {swap_freed_mb:.1f}MB swap", log_lines, log_scroll_pos)
                else:
                    log_scroll_pos = log_action(f"Cleared caches: freed {freed_mb:.1f}MB memory", log_lines, log_scroll_pos)
            # If minimal effect, don't log anything (cache clearing didn't help much)
        # If no effect, don't log success (as requested - only show if it actually worked)

    except PermissionError:
        log_scroll_pos = log_action("Cannot drop caches: insufficient permissions (VPS restriction)", log_lines, log_scroll_pos)
    except Exception as e:
        log_scroll_pos = log_action(f"Failed to drop caches: {e}", log_lines, log_scroll_pos)
    return log_scroll_pos


# Log actions
def log_action(action: str, log_lines: Optional[List[str]], log_scroll_pos: int) -> int:
    """Append a timestamped message to log_lines and the log file.

    Returns:
        Updated log scroll position.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    display_message = f"{timestamp} - {action}"
    # For log file, let logging module handle the timestamp
    logging.info(action)
    if log_lines is not None:
        log_lines.append(display_message)
        # Trim log lines to prevent unbounded memory growth
        if len(log_lines) > MAX_LOG_LINES:
            removed = len(log_lines) - MAX_LOG_LINES
            del log_lines[:removed]
            log_scroll_pos = max(0, log_scroll_pos - removed)
        # Adjust log_scroll_pos if the user is at the bottom
        if log_lines_visible > 0:
            if log_scroll_pos >= len(log_lines) - (log_lines_visible + 1):
                log_scroll_pos = len(log_lines) - log_lines_visible
        else:
            log_scroll_pos = max(len(log_lines) - 1, 0)
    return log_scroll_pos


# Render text with inline color codes
def render_colored_text(window: 'curses.window', y: int, start_x: int,
                        text: str, default_attr: int) -> None:
    """Render text with inline color codes like [GREEN]text[/GREEN]."""


    # Get window width to handle truncation properly
    max_y, max_x = window.getmaxyx()
    available_width = max_x - start_x - 1  # Leave space for border

    color_map = {
        'GREEN': color_attr_for("percent_ok") | curses.A_BOLD,
        'RED': color_attr_for("percent_high") | curses.A_BOLD,
        'YELLOW': color_attr_for("swap_label") | curses.A_BOLD,
        'CYAN': color_attr_for("mem_label") | curses.A_BOLD,
        'BLUE': color_attr_for("border") | curses.A_BOLD,
    }

    # First, strip color codes to check actual text length
    clean_text = re.sub(r'\[[A-Z]+\].*?\[/[A-Z]+\]', lambda m: m.group(0).split(']')[1].split('[')[0], text)

    # If clean text is too long, truncate the original text smartly
    if len(clean_text) > available_width:
        # Truncate but try to keep color codes intact
        text = text[:available_width + 20]  # Allow extra for color codes

    # Pattern to match [COLOR]text[/COLOR]
    pattern = r'\[([A-Z]+)\](.*?)\[/\1\]'

    current_x = start_x
    last_end = 0
    chars_written = 0

    try:
        for match in re.finditer(pattern, text):
            # Add text before the colored section
            if match.start() > last_end and chars_written < available_width:
                plain_text = text[last_end:match.start()]
                remaining_chars = available_width - chars_written
                plain_text = plain_text[:remaining_chars]
                if plain_text:
                    window.addstr(y, current_x, plain_text, default_attr)
                    current_x += len(plain_text)
                    chars_written += len(plain_text)

            # Add the colored text
            if chars_written < available_width:
                color_name = match.group(1)
                colored_text = match.group(2)
                remaining_chars = available_width - chars_written
                colored_text = colored_text[:remaining_chars]
                if colored_text:
                    color_attr = color_map.get(color_name, default_attr)
                    window.addstr(y, current_x, colored_text, color_attr)
                    current_x += len(colored_text)
                    chars_written += len(colored_text)

            last_end = match.end()

        # Add any remaining text
        if last_end < len(text) and chars_written < available_width:
            remaining_text = text[last_end:]
            remaining_chars = available_width - chars_written
            remaining_text = remaining_text[:remaining_chars]
            if remaining_text:
                window.addstr(y, current_x, remaining_text, default_attr)

    except curses.error:
        # Fallback: just render plain text without colors
        clean_fallback = re.sub(r'\[[A-Z]+\](.*?)\[/[A-Z]+\]', r'\1', text)
        clean_fallback = clean_fallback[:available_width]
        try:
            window.addstr(y, start_x, clean_fallback, default_attr)
        except curses.error:
            pass


# Update the log window
def update_log_window(log_lines: List[str], bottom_win: 'curses.window',
                      log_scroll_pos: int) -> int:
    """Redraw the log panel with search highlighting if active.

    Returns:
        The current log scroll position.
    """
    bottom_win.erase()
    bottom_win.bkgd(' ', color_attr_for("background"))
    if COLORS_ENABLED:
        bottom_win.attron(color_attr_for("border"))
    bottom_win.box()
    if COLORS_ENABLED:
        bottom_win.attroff(color_attr_for("border"))

    # Title
    title_attr = color_attr_for("title") | curses.A_BOLD
    bottom_win.addstr(0, 2, "Logs", title_attr)

    log_height = bottom_win.getmaxyx()[0] - 2  # Exclude border
    max_width = bottom_win.getmaxyx()[1] - 2

    # Build search match set for O(1) lookups
    search_match_set = set(_search_matches) if _in_search else set()
    current_match_line = _search_matches[_search_match_idx] if (
        _in_search and _search_matches and 0 <= _search_match_idx < len(_search_matches)
    ) else -1

    # Show search info in log title
    if _in_search and _search_query:
        search_info = f" [{len(_search_matches)} matches for '{_search_query}']"
        try:
            bottom_win.addstr(0, 7, search_info[:max_width - 8],
                              color_attr_for("swap_label") | curses.A_BOLD)
        except curses.error:
            pass

    visible_logs = log_lines[log_scroll_pos:log_scroll_pos + log_height]
    for idx, log in enumerate(visible_logs):
        line_global_idx = log_scroll_pos + idx
        ts_attr = color_attr_for("timestamp") | curses.A_BOLD
        txt_attr = color_attr_for("log_text")

        # Search highlighting
        if line_global_idx == current_match_line:
            txt_attr = color_attr_for("menu_hl")
            ts_attr = color_attr_for("menu_hl")
        elif line_global_idx in search_match_set:
            txt_attr = color_attr_for("percent_high") | curses.A_BOLD
            ts_attr = color_attr_for("percent_high") | curses.A_BOLD

        ts, msg = None, log
        sep_idx = log.find(" - ")
        if sep_idx != -1:
            ts = log[:sep_idx]
            msg = log[sep_idx + 3:]

        y = 1 + idx
        x = 1
        try:
            if ts:
                ts_str = ts[:max_width]
                bottom_win.addstr(y, x, ts_str, ts_attr)
                x += len(ts_str)
                if x < max_width:
                    bottom_win.addstr(y, x, " - ", txt_attr)
                    x += 3
            if x < max_width:
                # Parse and render colored text (let render_colored_text handle truncation)
                if line_global_idx == current_match_line or line_global_idx in search_match_set:
                    # For search matches, render plain text with highlight attr
                
                    clean_msg = re.sub(r'\[[A-Z]+\](.*?)\[/[A-Z]+\]', r'\1', msg)
                    bottom_win.addstr(y, x, clean_msg[:max_width - x], txt_attr)
                else:
                    render_colored_text(bottom_win, y, x, msg, txt_attr)
        except curses.error:
            pass
    bottom_win.refresh()
    return log_scroll_pos


# Status bar
def update_status_bar(status_win: 'curses.window', in_menu: bool,
                      in_theme: bool, in_search: bool) -> None:
    """Draw the persistent status bar at the bottom of the screen."""
    try:
        max_y, max_x = status_win.getmaxyx()
        status_win.erase()
        status_win.bkgd(' ', color_attr_for("statusbar"))
        attr = color_attr_for("statusbar") | curses.A_BOLD

        # Left side: current stats
        mem_pct, swap_pct = get_memory_and_swap_usage()
        left = f" Swap: {swap_pct:.1f}% | Mem: {mem_pct:.1f}%"

        # Right side: context-aware keybindings
        if in_menu:
            right = "Up/Dn:Nav  r:Restart  q/Esc:Close "
        elif in_theme:
            right = "Up/Dn:Nav  Enter:Apply  q/Esc:Cancel "
        elif in_search:
            right = "n:Next  N:Prev  Esc:Exit Search "
        elif _in_app_select:
            right = "Up/Dn:Nav  Enter:Detail  Esc:Cancel "
        else:
            right = "q:Quit  m:Menu  t:Theme  /:Search  d:Detail  ?:Help "

        # Draw left-aligned text
        status_win.addstr(0, 0, left[:max_x - 1], attr)

        # Fill middle with spaces
        filled = len(left)
        right_start = max(filled, max_x - len(right))
        if filled < right_start:
            status_win.addstr(0, filled, " " * (right_start - filled), attr)

        # Draw right-aligned text
        if right_start + len(right) <= max_x:
            status_win.addstr(0, right_start, right[:max_x - right_start], attr)

        status_win.noutrefresh()
    except curses.error:
        pass


# Sparkline rendering
def render_sparkline(values: List[float], width: int) -> str:
    """Convert a sequence of 0-100 values into a sparkline string."""
    if not values:
        return ""
    chars = []
    for v in values:
        clamped = max(0.0, min(100.0, v))
        idx = int(clamped / 100.0 * (len(SPARKLINE_CHARS) - 1))
        chars.append(SPARKLINE_CHARS[idx])
    return "".join(chars[-width:])


# Search functions
def enter_search_mode(stdscr: 'curses.window', status_win: 'curses.window') -> bool:
    """Capture search input from the user using the status bar area."""
    global _in_search, _search_query
    try:
        status_win.erase()
        status_win.bkgd(' ', color_attr_for("statusbar"))
        attr = color_attr_for("statusbar") | curses.A_BOLD
        status_win.addstr(0, 0, " Search: ", attr)
        status_win.refresh()

        curses.curs_set(1)
        stdscr.nodelay(False)

        query = ""
        while True:
            ch = stdscr.getch()
            if ch in (10, 13, curses.KEY_ENTER):
                break
            elif ch == 27:
                query = ""
                break
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                if query:
                    query = query[:-1]
            elif 32 <= ch <= 126:
                query += chr(ch)
            # Redraw input
            max_x = status_win.getmaxyx()[1]
            status_win.erase()
            status_win.bkgd(' ', color_attr_for("statusbar"))
            display = f" Search: {query}"
            status_win.addstr(0, 0, display[:max_x - 1], attr)
            status_win.refresh()

        curses.curs_set(0)
        stdscr.nodelay(True)

        if query:
            _search_query = query
            _in_search = True
            return True
        return False
    except curses.error:
        curses.curs_set(0)
        stdscr.nodelay(True)
        return False


def compute_search_matches(log_lines: List[str]) -> None:
    """Find all log line indices matching the current search query."""
    global _search_matches, _search_match_idx
    _search_matches = []
    if not _search_query:
        return
    query_lower = _search_query.lower()
    for i, line in enumerate(log_lines):
        if query_lower in line.lower():
            _search_matches.append(i)
    _search_match_idx = 0 if _search_matches else -1


def exit_search_mode() -> None:
    """Exit search mode and clear state."""
    global _in_search, _search_query, _search_matches, _search_match_idx
    _in_search = False
    _search_query = ""
    _search_matches = []
    _search_match_idx = -1


# Process detail view
def show_process_detail(stdscr: 'curses.window', app_name: str) -> None:
    """Full-screen overlay showing detailed process information."""
    height, width = stdscr.getmaxyx()
    detail_win = curses.newwin(height, width, 0, 0)
    detail_win.bkgd(' ', color_attr_for("background"))
    if COLORS_ENABLED:
        detail_win.attron(color_attr_for("border"))
    detail_win.box()
    if COLORS_ENABLED:
        detail_win.attroff(color_attr_for("border"))

    header = f"Process Detail: {app_name} (Press q/Esc to close)"
    try:
        detail_win.addstr(0, max(2, (width - len(header)) // 2), header,
                          color_attr_for("title") | curses.A_BOLD)
    except curses.error:
        pass

    row = 2
    txt_attr = color_attr_for("log_text")
    label_attr = color_attr_for("mem_label") | curses.A_BOLD
    val_attr = color_attr_for("percent_ok")

    # Get PIDs for this app
    pid_cache = get_monitored_pids_cached()
    app_data = pid_cache.get(app_name)
    if not app_data:
        try:
            detail_win.addstr(row, 2, f"No running processes found for {app_name}", txt_attr)
        except curses.error:
            pass
        detail_win.refresh()
        _wait_for_dismiss(stdscr)
        return

    pids = app_data['pids']
    service_name = monitored_apps.get(app_name, (app_name, False))[0]

    try:
        # Service name
        detail_win.addstr(row, 2, "Service: ", label_attr)
        detail_win.addstr(row, 11, service_name, val_attr)
        row += 1

        # Number of PIDs
        pid_label = f"PIDs ({len(pids)}): "
        detail_win.addstr(row, 2, pid_label, label_attr)
        pid_str = ", ".join(str(p) for p in pids[:20])
        if len(pids) > 20:
            pid_str += f" ... (+{len(pids) - 20} more)"
        detail_win.addstr(row, 2 + len(pid_label), pid_str[:width - 4 - len(pid_label)], val_attr)
        row += 2

        # Per-PID details header
        detail_win.addstr(row, 2, "PID Details:", label_attr)
        row += 1
        header_line = f"{'PID':>8}  {'Swap(KB)':>10}  {'RSS(MB)':>9}  {'VMS(MB)':>9}  {'CPU%':>6}  {'Status':>10}"
        detail_win.addstr(row, 2, header_line[:width - 4], label_attr)
        row += 1

        for pid in pids:
            if row >= height - 6:
                remaining = len(pids) - (row - 7)
                if remaining > 0:
                    detail_win.addstr(row, 2, f"... and {remaining} more processes", txt_attr)
                break
            try:
                proc = psutil.Process(pid)
                mem_info = proc.memory_info()
                cpu_pct = proc.cpu_percent(interval=0)
                status = proc.status()
                swap_kb = 0
                try:
                    with open(f"/proc/{pid}/status", "r") as f:
                        for sline in f:
                            if sline.startswith("VmSwap:"):
                                parts = sline.split()
                                if len(parts) >= 2 and parts[1].isdigit():
                                    swap_kb = int(parts[1])
                                break
                except Exception:
                    pass
                line = (f"{pid:>8}  {swap_kb:>10}  {mem_info.rss / (1024*1024):>9.1f}  "
                        f"{mem_info.vms / (1024*1024):>9.1f}  {cpu_pct:>6.1f}  {status:>10}")
                detail_win.addstr(row, 2, line[:width - 4], txt_attr)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                detail_win.addstr(row, 2, f"{pid:>8}  (not found or access denied)", txt_attr)
            row += 1

        # Systemctl status
        row += 1
        if row < height - 2:
            detail_win.addstr(row, 2, "systemctl status:", label_attr)
            row += 1
            try:
                result = subprocess.run(
                    ["systemctl", "status", service_name, "--no-pager", "-l"],
                    capture_output=True, text=True, timeout=5
                )
                for sline in result.stdout.split("\n"):
                    if row >= height - 2:
                        break
                    detail_win.addstr(row, 2, sline[:width - 4], txt_attr)
                    row += 1
            except Exception as e:
                detail_win.addstr(row, 2, f"Failed to get status: {e}", txt_attr)
    except curses.error:
        pass

    detail_win.refresh()
    _wait_for_dismiss(stdscr)


def _wait_for_dismiss(stdscr: 'curses.window') -> None:
    """Block until user presses q or Esc."""
    while True:
        key = stdscr.getch()
        if key in (ord('q'), 27):
            break
        time.sleep(0.1)


# Monitor swap usage
def monitor_swap_usage(log_lines: List[str], bottom_win: 'curses.window',
                       swap_high_threshold: float, swap_low_threshold: float,
                       log_scroll_pos: int, alert_manager: Optional['AlertManager'] = None,
                       metrics_db: Optional['MetricsDB'] = None) -> int:
    """Check swap usage and restart services if thresholds are exceeded.

    Returns:
        Updated log scroll position.
    """
    swap_percent = psutil.swap_memory().percent
    if swap_percent >= swap_high_threshold:
        log_scroll_pos = log_action(
            f"Swap usage is [RED]{swap_percent:.1f}%[/RED], which [RED]exceeds[/RED] the threshold of [YELLOW]{swap_high_threshold}%[/YELLOW].",
            log_lines, log_scroll_pos
        )
        if alert_manager:
            alert_manager.send_alert(
                "critical",
                f"Swap usage at {swap_percent:.1f}%, exceeds {swap_high_threshold}%",
                swap_percent
            )
        log_scroll_pos = drop_caches(log_lines, log_scroll_pos)
        time.sleep(2)
        swap_percent = psutil.swap_memory().percent
        if swap_percent >= swap_low_threshold:
            log_scroll_pos = log_action(
                f"Swap usage still too high at {swap_percent}%, restarting services based on swap usage.",
                log_lines, log_scroll_pos
            )
            # Get applications sorted by swap usage (highest swap users first)
            # Force refresh during monitoring to get most current data
            top_apps = get_top_swap_apps(force_refresh=True)
            apps_restarted = 0
            for app in top_apps:
                proc_name = app['name']
                if proc_name not in monitored_apps:
                    continue
                service_name = monitored_apps[proc_name][0]
                log_scroll_pos = restart_app(service_name, log_lines, log_scroll_pos, metrics_db)
                apps_restarted += 1
                time.sleep(2)
                swap_percent = psutil.swap_memory().percent
                if swap_percent < swap_low_threshold:
                    log_scroll_pos = log_action(
                        f"Done! Usage now at {swap_percent}% which is below the threshold of {swap_low_threshold}%",
                        log_lines, log_scroll_pos
                    )
                    log_scroll_pos = log_action("Resuming normal operations", log_lines, log_scroll_pos)
                    break
                else:
                    if apps_restarted == len(top_apps):
                        log_scroll_pos = log_action(
                            f"Done! Usage now at {swap_percent}% which is still not lower than {swap_low_threshold}%",
                            log_lines, log_scroll_pos
                        )
                        log_scroll_pos = log_action("Resuming normal operations", log_lines, log_scroll_pos)
                    else:
                        log_scroll_pos = log_action(
                            f"Swap usage still high at {swap_percent}%, continuing to restart services.",
                            log_lines, log_scroll_pos
                        )
        else:
            log_scroll_pos = log_action(
                f"Swap usage is [GREEN]{swap_percent:.1f}%[/GREEN], which is now [GREEN]below[/GREEN] the target of [CYAN]{swap_low_threshold}%[/CYAN].",
                log_lines, log_scroll_pos
            )
    else:
        log_scroll_pos = log_action(
            f"Swap usage is [GREEN]{swap_percent:.1f}%[/GREEN], which is [GREEN]below[/GREEN] the threshold of [YELLOW]{swap_high_threshold}%[/YELLOW].",
            log_lines, log_scroll_pos
        )
    return log_scroll_pos


# Set up the UI
def setup_ui(stdscr: 'curses.window') -> Tuple['curses.window', 'curses.window',
                                                'curses.window', 'curses.window']:
    """Create the four-panel layout: stats, apps, logs, and status bar."""
    height, width = stdscr.getmaxyx()

    # Apply background theme to stdscr via default bg (-1) so OSC 11 shows
    stdscr.bkgd(' ', color_attr_for("background"))
    stdscr.erase()

    # Title
    title = "SwapWatch 2.0"
    title_attr = color_attr_for("title") | curses.A_BOLD
    stdscr.addstr(0, max(0, (width - len(title)) // 2), title, title_attr)
    stdscr.refresh()

    top_left_h = 7
    top_right_h = 7
    bottom_h = height - top_left_h - 3 - 1  # -1 for status bar at bottom
    top_left_w = width // 2
    top_right_w = width - top_left_w

    # Create windows starting from line 2 to avoid overlapping the title
    top_left_win = curses.newwin(top_left_h, top_left_w, 2, 0)
    top_right_win = curses.newwin(top_right_h, top_right_w, 2, top_left_w)
    bottom_win = curses.newwin(bottom_h, width, top_left_h + 2, 0)
    status_win = curses.newwin(1, width, height - 1, 0)

    # Themed backgrounds for windows (inherit default bg)
    for w in (top_left_win, top_right_win, bottom_win):
        w.bkgd(' ', color_attr_for("background"))
    status_win.bkgd(' ', color_attr_for("statusbar"))

    # Draw borders and titles with colors
    if COLORS_ENABLED:
        top_left_win.attron(color_attr_for("border"))
    top_left_win.box()
    if COLORS_ENABLED:
        top_left_win.attroff(color_attr_for("border"))
    top_left_win.addstr(0, 2, "Memory & Swap Usage", color_attr_for("title") | curses.A_BOLD)
    top_left_win.refresh()

    if COLORS_ENABLED:
        top_right_win.attron(color_attr_for("border"))
    top_right_win.box()
    if COLORS_ENABLED:
        top_right_win.attroff(color_attr_for("border"))
    top_right_win.addstr(0, 2, "Top Swap Using Apps", color_attr_for("title") | curses.A_BOLD)
    top_right_win.refresh()

    if COLORS_ENABLED:
        bottom_win.attron(color_attr_for("border"))
    bottom_win.box()
    if COLORS_ENABLED:
        bottom_win.attroff(color_attr_for("border"))
    bottom_win.addstr(0, 2, "Logs", color_attr_for("title") | curses.A_BOLD)
    bottom_win.refresh()

    return top_left_win, top_right_win, bottom_win, status_win


# Performance-optimized helper functions
def batch_read_swap_data(pids: List[int]) -> Dict[int, int]:
    """Efficiently read swap data for multiple PIDs at once."""
    global _performance_stats
    swap_data = {}

    for pid in pids:
        try:
            _performance_stats['file_reads'] += 1
            with open(f'/proc/{pid}/status', 'r') as f:
                content = f.read()
                for line in content.split('\n'):
                    if line.startswith('VmSwap:'):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            swap_data[pid] = int(parts[1]) * 1024  # Convert KB to bytes
                        else:
                            swap_data[pid] = 0
                        break
                else:
                    swap_data[pid] = 0  # No swap line found
        except (FileNotFoundError, PermissionError, ValueError, OSError, IOError):
            swap_data[pid] = 0
            continue

    return swap_data


def get_monitored_pids_cached(force_refresh: bool = False) -> Dict[str, dict]:
    """Get PIDs of monitored processes with caching to reduce expensive scans."""
    global _cached_monitored_pids, _last_pid_scan, _performance_stats

    current_time = time.time()

    # Use cached data if recent (within 30 seconds) and not forcing refresh
    if not force_refresh and current_time - _last_pid_scan < 30 and _cached_monitored_pids:
        _performance_stats['cache_hits'] += 1
        return _cached_monitored_pids

    # Time for a fresh scan
    start_time = time.time()
    _performance_stats['process_scans'] += 1

    monitored_process_names = list(monitored_apps.keys())
    new_pid_cache = {}

    # Single pass through all processes
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            proc_name = (proc.info['name'] or '').lower()
            exe = (proc.info.get('exe') or '').lower()
            cmdline_list = [x.lower() for x in (proc.info.get('cmdline') or [])]

            for mon_name in monitored_process_names:
                mon_l = mon_name.lower()
                if (
                    mon_l in proc_name
                    or (exe and mon_l in exe)
                    or any(mon_l in arg for arg in cmdline_list)
                ):
                    pid = proc.info['pid']
                    include_children = monitored_apps[mon_name][1]

                    if mon_name not in new_pid_cache:
                        new_pid_cache[mon_name] = {
                            'pids': [],
                            'include_children': include_children,
                            'has_children': False
                        }

                    new_pid_cache[mon_name]['pids'].append(pid)

                    # Add children if configured
                    if include_children:
                        try:
                            children = proc.children(recursive=True)
                            if children:
                                new_pid_cache[mon_name]['has_children'] = True
                                for child in children:
                                    try:
                                        new_pid_cache[mon_name]['pids'].append(child.pid)
                                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                                        continue
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    break  # Found match, don't check other monitored names for this process

        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError, ProcessLookupError):
            continue

    _cached_monitored_pids = new_pid_cache
    _last_pid_scan = current_time
    _performance_stats['last_scan_duration'] = time.time() - start_time

    return new_pid_cache


# Get top swap using apps (robust and optimized)
def get_top_swap_apps(force_refresh: bool = False) -> List[dict]:
    """Get swap usage by monitored apps with intelligent caching for better performance."""
    global _cached_swap_data, _last_swap_scan, _performance_stats

    current_time = time.time()

    # Use adaptive cache time - longer cache during low activity, shorter during high activity
    adaptive_cache_time = _performance_stats['adaptive_cache_time']

    # Use cached data if recent and not forcing refresh
    if not force_refresh and current_time - _last_swap_scan < adaptive_cache_time and _cached_swap_data:
        _performance_stats['cache_hits'] += 1
        return _cached_swap_data

    # Get total swap (with fallback)
    total_swap = psutil.swap_memory().total
    if total_swap == 0:
        try:
            _performance_stats['file_reads'] += 1
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('SwapTotal:'):
                        total_swap = int(line.split()[1]) * 1024  # Convert KB to bytes
                        break
        except Exception:
            pass

    # If system has no swap at all, nothing to report
    if total_swap == 0:
        _cached_swap_data = []
        _last_swap_scan = current_time
        return []

    # Get current monitored PIDs (uses its own caching)
    pid_cache = get_monitored_pids_cached()

    # Collect all PIDs for batch reading
    all_pids = []
    for app_data in pid_cache.values():
        all_pids.extend(app_data['pids'])

    # Batch read swap data for all PIDs at once
    swap_data = batch_read_swap_data(all_pids) if all_pids else {}

    # Calculate totals per application
    app_swap_usage = []
    for mon_name, app_data in pid_cache.items():
        total_swap_bytes = 0

        # Sum swap usage for all PIDs of this application
        for pid in app_data['pids']:
            total_swap_bytes += swap_data.get(pid, 0)

        # Calculate percentage
        swap_percent = (total_swap_bytes / total_swap) * 100 if total_swap else 0.0

        app_swap_usage.append({
            'name': mon_name,
            'swap_bytes': total_swap_bytes,
            'swap_percent': swap_percent,
            'include_children': app_data['include_children'],
            'has_children': app_data['has_children']
        })

    # Sort by swap usage (highest first)
    app_swap_usage.sort(key=lambda x: x['swap_percent'], reverse=True)

    # Cache the results
    _cached_swap_data = app_swap_usage
    _last_swap_scan = current_time

    # Adaptive cache timing: adjust based on swap activity and scan performance
    current_swap_usage = psutil.swap_memory().percent
    scan_duration = _performance_stats['last_scan_duration']

    # Shorter cache time if high swap usage or slow scans (system under stress)
    if current_swap_usage > 50 or scan_duration > 2.0:
        _performance_stats['adaptive_cache_time'] = max(10, _performance_stats['adaptive_cache_time'] - 1)
    # Longer cache time if low swap usage and fast scans (system is idle)
    elif current_swap_usage < 20 and scan_duration < 0.5:
        _performance_stats['adaptive_cache_time'] = min(30, _performance_stats['adaptive_cache_time'] + 2)

    return app_swap_usage


# Update dynamic data on the screen (colorized)
def update_ui(top_left_win: 'curses.window', top_right_win: 'curses.window') -> None:
    """Refresh the stats and top-apps panels with current data."""
    mem_usage, swap_usage = get_memory_and_swap_usage()

    # Border & title
    if COLORS_ENABLED:
        top_left_win.attron(color_attr_for("border"))
    top_left_win.box()
    if COLORS_ENABLED:
        top_left_win.attroff(color_attr_for("border"))
    top_left_win.addstr(0, 2, "Memory & Swap Usage", color_attr_for("title") | curses.A_BOLD)

    # Labels and values
    mem_label_attr = color_attr_for("mem_label") | curses.A_BOLD
    swap_label_attr = color_attr_for("swap_label") | curses.A_BOLD
    percent_ok_attr = color_attr_for("percent_ok") | curses.A_BOLD
    percent_high_attr = color_attr_for("percent_high") | curses.A_BOLD

    # Memory Usage line
    top_left_win.addstr(2, 2, "Memory Usage: ", mem_label_attr)
    try:
        top_left_win.addstr(2, 2 + len("Memory Usage: "), f"{mem_usage:.2f}%", percent_ok_attr)
    except curses.error:
        pass

    # Swap Usage line (color depends on threshold)
    top_left_win.addstr(3, 2, "Swap Usage: ", swap_label_attr)
    swap_attr = percent_high_attr if swap_usage >= SWAP_HIGH_THRESHOLD else percent_ok_attr
    try:
        top_left_win.addstr(3, 2 + len("Swap Usage: "), f"{swap_usage:.2f}%", swap_attr)
    except curses.error:
        pass

    # Add performance stats (only if we have meaningful data)
    if _performance_stats['process_scans'] > 0:
        perf_attr = color_attr_for("timestamp") | curses.A_DIM
        try:
            cache_hit_rate = (_performance_stats['cache_hits'] / max(1, _performance_stats['cache_hits'] + _performance_stats['process_scans'])) * 100
            adaptive_time = _performance_stats['adaptive_cache_time']
            top_left_win.addstr(4, 2, f"Perf: {cache_hit_rate:.0f}% cache hits, {adaptive_time}s adaptive cache", perf_attr)
        except curses.error:
            pass

    # Sparkline on row 5
    _swap_history.append(swap_usage)
    if _swap_history:
        max_spark_width = top_left_win.getmaxyx()[1] - 4
        spark_str = render_sparkline(list(_swap_history), max_spark_width)
        spark_attr = color_attr_for("percent_high") if swap_usage >= SWAP_HIGH_THRESHOLD else color_attr_for("percent_ok")
        try:
            top_left_win.addstr(5, 2, spark_str, spark_attr)
        except curses.error:
            pass

    top_left_win.refresh()

    # Top apps by swap usage
    top_apps = get_top_swap_apps()[:10]  # Get top 10 swap-using apps

    if COLORS_ENABLED:
        top_right_win.attron(color_attr_for("border"))
    top_right_win.box()
    if COLORS_ENABLED:
        top_right_win.attroff(color_attr_for("border"))
    top_right_win.addstr(0, 2, "Top Swap Using Apps", color_attr_for("title") | curses.A_BOLD)

    # Clear only the area where app data is displayed
    max_display_lines = top_right_win.getmaxyx()[0] - 3  # Account for border and title
    for idx in range(max_display_lines):
        try:
            top_right_win.addstr(2 + idx, 2, " " * (top_right_win.getmaxyx()[1] - 4))
        except curses.error:
            pass

    # Display apps (up to what fits in the window)
    display_count = min(len(top_apps), max_display_lines)
    for idx in range(display_count):
        app = top_apps[idx]
        app_name = app['name']
        swap_percent = app['swap_percent']
        suffix = " (Children)" if (app['include_children'] and app['has_children']) else ""
        y = 2 + idx
        try:
            if _in_app_select and idx == _app_select_idx:
                # Highlighted selection row
                line_text = f"{app_name}: {swap_percent:.2f}%{suffix}"
                top_right_win.attron(color_attr_for("menu_hl"))
                top_right_win.addstr(y, 2, line_text[:top_right_win.getmaxyx()[1] - 4])
                top_right_win.attroff(color_attr_for("menu_hl"))
            else:
                label_attr = color_attr_for("swap_label") | curses.A_BOLD
                value_attr = percent_high_attr if swap_percent >= 1.0 else percent_ok_attr
                top_right_win.addstr(y, 2, f"{app_name}: ", label_attr)
                top_right_win.addstr(y, 2 + len(app_name) + 2, f"{swap_percent:.2f}%{suffix}", value_attr)
        except curses.error:
            pass
    top_right_win.refresh()


# --------- NON-FLASHING WINDOWS ---------
def draw_menu(stdscr: 'curses.window', selected_idx: int,
              existing_win: Optional['curses.window'] = None) -> 'curses.window':
    """Non-flashing menu: reuse a dedicated window and avoid clearing stdscr."""
    height, width = stdscr.getmaxyx()
    menu_win = existing_win or curses.newwin(height, width, 0, 0)

    # Themed background + minimal redraw
    menu_win.bkgd(' ', color_attr_for("background"))
    menu_win.erase()

    if COLORS_ENABLED:
        menu_win.attron(color_attr_for("border"))
    menu_win.box()
    if COLORS_ENABLED:
        menu_win.attroff(color_attr_for("border"))

    header = "Monitored Applications (Press 'r' to restart, 'q'/Esc to exit menu)"
    try:
        menu_win.addstr(0, max(2, (width - len(header)) // 2), header, color_attr_for("title") | curses.A_BOLD)
    except curses.error:
        pass

    apps = list(monitored_apps.keys())
    max_items = max(1, height - 4)  # space for border/header

    # Clamp selection
    selected_idx = max(0, min(selected_idx, len(apps) - 1))

    # Compute windowed list range
    if len(apps) <= max_items:
        start_idx, end_idx = 0, len(apps)
    else:
        half = max_items // 2
        if selected_idx < half:
            start_idx = 0
        elif selected_idx > len(apps) - half:
            start_idx = len(apps) - max_items
        else:
            start_idx = selected_idx - half
        end_idx = start_idx + max_items

    display_apps = apps[start_idx:end_idx]
    for i, app_name in enumerate(display_apps):
        y = 2 + i
        try:
            if start_idx + i == selected_idx:
                menu_win.attron(color_attr_for("menu_hl"))
                menu_win.addstr(y, 2, app_name)
                menu_win.attroff(color_attr_for("menu_hl"))
            else:
                menu_win.addstr(y, 2, app_name, color_attr_for("menu_text"))
        except curses.error:
            pass

    menu_win.refresh()
    return menu_win


def draw_theme_dialog(stdscr: 'curses.window', selected_idx: int,
                      themes: List[str],
                      existing_win: Optional['curses.window'] = None) -> 'curses.window':
    """Theme selector dialog (minimal redraw, reuses its own window)."""
    height, width = stdscr.getmaxyx()
    theme_win = existing_win or curses.newwin(height, width, 0, 0)
    theme_win.bkgd(' ', color_attr_for("background"))
    theme_win.erase()

    if COLORS_ENABLED:
        theme_win.attron(color_attr_for("border"))
    theme_win.box()
    if COLORS_ENABLED:
        theme_win.attroff(color_attr_for("border"))

    header = "Theme Selector (Enter to apply, 'q'/Esc to cancel)"
    theme_win.addstr(0, max(2, (width - len(header)) // 2), header, color_attr_for("title") | curses.A_BOLD)

    if not themes:
        msg = f"No themes found in {THEME_DIR}"
        theme_win.addstr(2, 2, msg, color_attr_for("log_text"))
        theme_win.refresh()
        return theme_win

    max_items = height - 4
    selected_idx = max(0, min(selected_idx, len(themes) - 1))
    if len(themes) <= max_items:
        start_idx = 0
        end_idx = len(themes)
    else:
        half = max_items // 2
        if selected_idx < half:
            start_idx = 0
        elif selected_idx > len(themes) - half:
            start_idx = len(themes) - max_items
        else:
            start_idx = selected_idx - half
        end_idx = start_idx + max_items

    display = themes[start_idx:end_idx]
    for i, fname in enumerate(display):
        y = 2 + i
        try:
            if start_idx + i == selected_idx:
                theme_win.attron(color_attr_for("menu_hl"))
                theme_win.addstr(y, 2, fname)
                theme_win.attroff(color_attr_for("menu_hl"))
            else:
                theme_win.addstr(y, 2, fname, color_attr_for("menu_text"))
        except curses.error:
            pass

    theme_win.refresh()
    return theme_win


def show_help(stdscr: 'curses.window') -> None:
    """Help overlay (reused window pattern)."""
    height, width = stdscr.getmaxyx()
    help_win = curses.newwin(height, width, 0, 0)
    help_win.bkgd(' ', color_attr_for("background"))
    if COLORS_ENABLED:
        help_win.attron(color_attr_for("border"))
    help_win.box()
    if COLORS_ENABLED:
        help_win.attroff(color_attr_for("border"))

    lines = APP_HELP_TEXT.strip().split('\n')
    for idx, line in enumerate(lines):
        try:
            help_win.addstr(1 + idx, 2, line, color_attr_for("log_text"))
        except curses.error:
            pass
    help_win.refresh()
    while True:
        key = stdscr.getch()
        if key == ord('q') or key == 27:
            break
        time.sleep(0.1)


# Run the curses app
def main() -> None:
    """Entry point: parse args, load config, and run the curses event loop."""
    global log_lines_visible

    # Parse command-line arguments
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--swap-high', type=float, help='Set the swap high threshold percentage (default: 80).')
    parser.add_argument('--swap-low', type=float, help='Set the swap low threshold percentage (default: 65).')
    parser.add_argument('--config', type=str, default=DEFAULT_CONFIG_PATH,
                        help='Path to TOML config file (default: /etc/swapwatch/config.toml).')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message and exit.')
    args = parser.parse_args()

    if args.help:
        print(CMD_HELP_TEXT)
        sys.exit(0)

    # Load config file (must happen before threshold defaults are used)
    config = load_config(args.config)
    apply_config(config)

    # Reconfigure logging if config changed the log file
    if config.get("general", {}).get("log_file"):
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.basicConfig(
            filename=LOG_FILE, level=logging.INFO,
            format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
        )

    # CLI args override config (which overrides hardcoded defaults)
    swap_high_threshold = args.swap_high if args.swap_high is not None else SWAP_HIGH_THRESHOLD
    swap_low_threshold = args.swap_low if args.swap_low is not None else SWAP_LOW_THRESHOLD

    # Validate swap thresholds
    if swap_low_threshold >= swap_high_threshold:
        print("Error: swap-low threshold must be less than swap-high threshold.")
        sys.exit(1)
    if not (0 <= swap_low_threshold <= 100 and 0 <= swap_high_threshold <= 100):
        print("Error: Thresholds must be between 0 and 100.")
        sys.exit(1)

    # Ensure the script is run as root
    if os.geteuid() != 0:
        print("This script must be run as root to function properly.")
        sys.exit(1)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Instantiate alerting and metrics systems
    alert_manager = AlertManager(config)
    metrics_db = MetricsDB(config)

    # BEFORE drawing anything: set terminal default bg to theme truecolor
    # (We don't know theme yet; set a sane dark fallback to avoid flash)
    try:
        osc11_set_bg("#1b1b27")  # dark fallback until theme loads
    except Exception:
        pass

    stdscr = init_curses()

    # Load theme (try default if present) and apply OSC 11 + pairs
    theme_values = DEFAULT_THEME_VALUES.copy()
    if COLORS_ENABLED:
        themes_available = list_theme_files()
        if DEFAULT_THEME_NAME in themes_available:
            theme_values = load_theme_by_name(DEFAULT_THEME_NAME)
        else:
            apply_theme(theme_values)
    else:
        # still set bgcolor from defaults so background is dark even without curses colors
        osc11_set_bg(value_to_hex(theme_values.get("background_bg", "black")))

    log_lines = []
    log_scroll_pos = 0  # For scrolling the log window
    in_menu = False
    in_theme = False
    menu_selected_idx = 0
    theme_selected_idx = 0
    menu_win = None   # persistent menu window to avoid flashing
    theme_win = None  # persistent theme window to avoid flashing

    try:
        top_left_win, top_right_win, bottom_win, status_win = setup_ui(stdscr)

        # Determine the number of visible log lines
        log_lines_visible = bottom_win.getmaxyx()[0] - 2  # Exclude borders

        # Initial logs/UI
        log_scroll_pos = log_action("SwapWatch 2.0 - Optimized monitoring started", log_lines, log_scroll_pos)
        log_scroll_pos = log_action("Performance features: PID caching, batch I/O, smart refresh", log_lines, log_scroll_pos)
        update_ui(top_left_win, top_right_win)
        update_log_window(log_lines, bottom_win, log_scroll_pos)
        update_status_bar(status_win, in_menu, in_theme, _in_search)
        curses.doupdate()
        log_scroll_pos = monitor_swap_usage(log_lines, bottom_win, swap_high_threshold, swap_low_threshold,
                                            log_scroll_pos, alert_manager, metrics_db)
        update_log_window(log_lines, bottom_win, log_scroll_pos)

        last_check_time = time.time()
        last_ui_update_time = time.time()
        while not _shutdown_requested:
            current_time = time.time()

            # Update UI at specified interval
            if current_time - last_ui_update_time >= UI_UPDATE_INTERVAL:
                if not in_menu and not in_theme:
                    update_ui(top_left_win, top_right_win)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                    update_status_bar(status_win, in_menu, in_theme, _in_search)
                    curses.doupdate()
                    # Record metrics sample (self-throttled by sample_interval)
                    if metrics_db.enabled:
                        mem_pct, swap_pct = get_memory_and_swap_usage()
                        metrics_db.record_sample(swap_pct, mem_pct, get_top_swap_apps())
                last_ui_update_time = current_time

            # Check swap usage every CHECK_INTERVAL seconds
            if current_time - last_check_time >= CHECK_INTERVAL:
                log_scroll_pos = monitor_swap_usage(log_lines, bottom_win, swap_high_threshold, swap_low_threshold,
                                                    log_scroll_pos, alert_manager, metrics_db)
                last_check_time = current_time

            # Handle user input (single read per loop)
            key = stdscr.getch()

            # Theme dialog interaction
            if in_theme:
                themes = list_theme_files()
                if theme_win is None:
                    theme_win = draw_theme_dialog(stdscr, theme_selected_idx, themes, None)

                if not themes:
                    if key in (27, ord('q'), curses.KEY_ENTER, 10, 13):
                        in_theme = False
                        theme_win = None
                        top_left_win, top_right_win, bottom_win, status_win = setup_ui(stdscr)
                        update_ui(top_left_win, top_right_win)
                        update_log_window(log_lines, bottom_win, log_scroll_pos)
                        update_status_bar(status_win, in_menu, in_theme, _in_search)
                        curses.doupdate()
                    time.sleep(0.05)
                    continue

                if key == curses.KEY_UP:
                    theme_selected_idx = max(0, theme_selected_idx - 1)
                    theme_win = draw_theme_dialog(stdscr, theme_selected_idx, themes, theme_win)
                elif key == curses.KEY_DOWN:
                    theme_selected_idx = min(len(themes) - 1, theme_selected_idx + 1)
                    theme_win = draw_theme_dialog(stdscr, theme_selected_idx, themes, theme_win)
                elif key in (10, 13, curses.KEY_ENTER):
                    chosen = themes[theme_selected_idx]
                    theme_values = load_theme_by_name(chosen)
                    in_theme = False
                    theme_win = None
                    top_left_win, top_right_win, bottom_win, status_win = setup_ui(stdscr)
                    update_ui(top_left_win, top_right_win)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                    update_status_bar(status_win, in_menu, in_theme, _in_search)
                    curses.doupdate()
                elif key in (27, ord('q')):
                    in_theme = False
                    theme_win = None
                    top_left_win, top_right_win, bottom_win, status_win = setup_ui(stdscr)
                    update_ui(top_left_win, top_right_win)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                    update_status_bar(status_win, in_menu, in_theme, _in_search)
                    curses.doupdate()
                time.sleep(0.05)
                continue

            # Monitored-apps menu interaction (reuse window to avoid flashing)
            if in_menu:
                if menu_win is None:
                    menu_win = draw_menu(stdscr, menu_selected_idx, None)

                if key == curses.KEY_UP:
                    menu_selected_idx = max(0, menu_selected_idx - 1)
                    menu_win = draw_menu(stdscr, menu_selected_idx, menu_win)
                elif key == curses.KEY_DOWN:
                    menu_selected_idx = min(len(monitored_apps) - 1, menu_selected_idx + 1)
                    menu_win = draw_menu(stdscr, menu_selected_idx, menu_win)
                elif key == ord('r'):
                    proc_name = list(monitored_apps.keys())[menu_selected_idx]
                    service_name = monitored_apps[proc_name][0]
                    log_scroll_pos = restart_app(service_name, log_lines, log_scroll_pos, metrics_db)
                    menu_win = draw_menu(stdscr, menu_selected_idx, menu_win)
                elif key in (ord('q'), 27):
                    in_menu = False
                    menu_win = None
                    top_left_win, top_right_win, bottom_win, status_win = setup_ui(stdscr)
                    update_ui(top_left_win, top_right_win)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                    update_status_bar(status_win, in_menu, in_theme, _in_search)
                    curses.doupdate()
                time.sleep(0.05)
                continue

            # Handle terminal resize
            if key == curses.KEY_RESIZE:
                stdscr.clear()
                stdscr.refresh()
                top_left_win, top_right_win, bottom_win, status_win = setup_ui(stdscr)
                log_lines_visible = bottom_win.getmaxyx()[0] - 2
                update_ui(top_left_win, top_right_win)
                update_log_window(log_lines, bottom_win, log_scroll_pos)
                update_status_bar(status_win, in_menu, in_theme, _in_search)
                curses.doupdate()
                continue

            # Global key handling
            if key == ord('q'):
                break
            elif key == ord('m'):
                in_menu = True
                menu_win = draw_menu(stdscr, menu_selected_idx, None)
                update_status_bar(status_win, in_menu, in_theme, _in_search)
                curses.doupdate()
            elif key == ord('t'):
                in_theme = True
                theme_selected_idx = 0
                theme_win = None
                update_status_bar(status_win, in_menu, in_theme, _in_search)
                curses.doupdate()
            elif key == ord('c'):
                log_scroll_pos = log_action("Forcing cache refresh...", log_lines, log_scroll_pos)
                get_monitored_pids_cached(force_refresh=True)
                get_top_swap_apps(force_refresh=True)
                update_ui(top_left_win, top_right_win)
                update_log_window(log_lines, bottom_win, log_scroll_pos)
                log_scroll_pos = log_action("Cache refreshed - data updated", log_lines, log_scroll_pos)
            elif key == ord('?'):
                show_help(stdscr)
                top_left_win, top_right_win, bottom_win, status_win = setup_ui(stdscr)
                update_ui(top_left_win, top_right_win)
                update_log_window(log_lines, bottom_win, log_scroll_pos)
                update_status_bar(status_win, in_menu, in_theme, _in_search)
                curses.doupdate()
            elif key == ord('/'):
                # Enter search mode
                if enter_search_mode(stdscr, status_win):
                    compute_search_matches(log_lines)
                    if _search_matches:
                        log_scroll_pos = max(0, _search_matches[0] - log_lines_visible // 2)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                update_status_bar(status_win, in_menu, in_theme, _in_search)
                curses.doupdate()
            elif key == ord('n') and _in_search:
                # Next search match
                if _search_matches and _search_match_idx < len(_search_matches) - 1:
                    _search_match_idx += 1
                    log_scroll_pos = max(0, _search_matches[_search_match_idx] - log_lines_visible // 2)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
            elif key == ord('N') and _in_search:
                # Previous search match
                if _search_matches and _search_match_idx > 0:
                    _search_match_idx -= 1
                    log_scroll_pos = max(0, _search_matches[_search_match_idx] - log_lines_visible // 2)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
            elif key == ord('d'):
                # Toggle app-select mode or open detail
                global _in_app_select, _app_select_idx
                if not _in_app_select:
                    _in_app_select = True
                    _app_select_idx = 0
                    update_ui(top_left_win, top_right_win)
                    update_status_bar(status_win, in_menu, in_theme, _in_search)
                    curses.doupdate()
                else:
                    top_apps = get_top_swap_apps()[:10]
                    if top_apps and 0 <= _app_select_idx < len(top_apps):
                        show_process_detail(stdscr, top_apps[_app_select_idx]['name'])
                        _in_app_select = False
                        top_left_win, top_right_win, bottom_win, status_win = setup_ui(stdscr)
                        update_ui(top_left_win, top_right_win)
                        update_log_window(log_lines, bottom_win, log_scroll_pos)
                        update_status_bar(status_win, in_menu, in_theme, _in_search)
                        curses.doupdate()
            elif key == 27:
                # Esc: exit search or app-select
                if _in_search:
                    exit_search_mode()
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                    update_status_bar(status_win, in_menu, in_theme, _in_search)
                    curses.doupdate()
                elif _in_app_select:
                    _in_app_select = False
                    update_ui(top_left_win, top_right_win)
                    update_status_bar(status_win, in_menu, in_theme, _in_search)
                    curses.doupdate()
            elif key in (10, 13, curses.KEY_ENTER) and _in_app_select:
                # Enter in app-select opens detail
                top_apps = get_top_swap_apps()[:10]
                if top_apps and 0 <= _app_select_idx < len(top_apps):
                    show_process_detail(stdscr, top_apps[_app_select_idx]['name'])
                    _in_app_select = False
                    top_left_win, top_right_win, bottom_win, status_win = setup_ui(stdscr)
                    update_ui(top_left_win, top_right_win)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                    update_status_bar(status_win, in_menu, in_theme, _in_search)
                    curses.doupdate()
            elif key == curses.KEY_UP:
                if _in_app_select:
                    _app_select_idx = max(0, _app_select_idx - 1)
                    update_ui(top_left_win, top_right_win)
                else:
                    log_scroll_pos = max(0, log_scroll_pos - 1)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
            elif key == curses.KEY_DOWN:
                if _in_app_select:
                    top_apps = get_top_swap_apps()[:10]
                    _app_select_idx = min(max(0, len(top_apps) - 1), _app_select_idx + 1)
                    update_ui(top_left_win, top_right_win)
                else:
                    max_scroll = max(len(log_lines) - log_lines_visible, 0)
                    log_scroll_pos = min(max_scroll, log_scroll_pos + 1)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)

            time.sleep(0.1)

        # Graceful shutdown
        if _shutdown_requested:
            log_action("Shutdown signal received, exiting...", log_lines, log_scroll_pos)
    finally:
        metrics_db.close()
        close_curses(stdscr)


if __name__ == '__main__':
    main()

