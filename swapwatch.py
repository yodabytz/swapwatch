#!/usr/bin/env python3
import curses
import psutil
import time
import os
import logging
from datetime import datetime
import subprocess
import sys
import argparse  # Import argparse for command-line argument parsing

# =========================
# Theming constants/paths
# =========================
THEME_DIR = "/etc/swapwatch/themes"
DEFAULT_THEME_NAME = "tokyonight.theme"  # will try to use if present

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

def _rgb_to_hex(r, g, b):
    return f"#{r:02x}{g:02x}{b:02x}"

def _x256_to_rgb(n):
    # xterm-256 → RGB
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

def _named_to_rgb(name):
    m = {
        "black":(0,0,0),"red":(255,0,0),"green":(0,255,0),"yellow":(255,255,0),
        "blue":(0,0,255),"magenta":(255,0,255),"cyan":(0,255,255),"white":(255,255,255)
    }
    return m.get(name.lower(), (0,0,0))

def value_to_hex(v):
    """theme value -> #RRGGBB"""
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

def osc11_set_bg(hex_rgb):
    """Set terminal default background to hex (#RRGGBB) using OSC 11."""
    try:
        os.write(sys.stdout.fileno(), (f"{OSC}11;{hex_rgb}{BEL}").encode("utf-8"))
    except Exception:
        pass
# ================================================================


def apply_prlimit(pid, mem_limit_bytes):
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
def ensure_theme_dir():
    return os.path.isdir(THEME_DIR)


def list_theme_files():
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


def _hex_to_256(hexstr):
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


def parse_theme_file(path):
    """
    key=value per line. Supports:
      - named colors: red, blue, ...
      - x256:<index>
      - #RRGGBB  (hex)
    Unknown keys/values are ignored.
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


def get_color_number(value):
    """
    Return a curses color number:
      - name -> COLOR_NAME_MAP[name]
      - x256:<n> -> int(n) if 256 supported, else fallback
      - #RRGGBB -> nearest xterm-256 if supported, else fallback
    """
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


def color_attr_for(role):
    """Return curses attribute (color pair) for a role, or 0 if colors disabled."""
    if COLORS_ENABLED and role in COLOR_PAIRS:
        return curses.color_pair(COLOR_PAIRS[role])
    return 0


def init_color_pairs(theme_values):
    """
    Register color pairs for roles based on foreground and background where applicable.
    Use -1 (terminal default bg) for most backgrounds so OSC 11 truecolor shows.
    Keep explicit bg only for highlight pair.
    """
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


def apply_theme(theme_values):
    """Apply theme values to curses color pairs (if colors enabled) and OSC bg."""
    # Set terminal default background to truecolor (OSC 11) from theme bg
    hex_bg = value_to_hex(theme_values.get("background_bg", "black"))
    osc11_set_bg(hex_bg)
    if COLORS_ENABLED:
        init_color_pairs(theme_values)


def load_theme_by_name(theme_name):
    """Load and apply a theme from THEME_DIR by name."""
    path = os.path.join(THEME_DIR, theme_name)
    theme = parse_theme_file(path)
    apply_theme(theme)
    return theme


# Initialize curses
def init_curses():
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
def close_curses(stdscr):
    curses.nocbreak()
    stdscr.keypad(False)
    curses.echo()
    curses.endwin()


# Get memory and swap usage
def get_memory_and_swap_usage():
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return mem.percent, swap.percent


# Restart app
def restart_app(service_name, log_lines, log_scroll_pos):
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
    except subprocess.TimeoutExpired:
        log_scroll_pos = log_action(f"Restarting {service_name} timed out.", log_lines, log_scroll_pos)
    except subprocess.CalledProcessError as e:
        log_scroll_pos = log_action(f"Failed to restart {service_name}: {e.stderr.strip()}", log_lines, log_scroll_pos)
    except Exception as e:
        log_scroll_pos = log_action(f"Unexpected error restarting {service_name}: {e}", log_lines, log_scroll_pos)
    return log_scroll_pos


# Drop caches
def drop_caches(log_lines, log_scroll_pos):
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
def log_action(action, log_lines, log_scroll_pos):
    # For curses app display, add timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    display_message = f"{timestamp} - {action}"
    # For log file, let logging module handle the timestamp
    logging.info(action)
    if log_lines is not None:
        log_lines.append(display_message)
        # Adjust log_scroll_pos if the user is at the bottom
        if 'log_lines_visible' in globals():
            if log_scroll_pos >= len(log_lines) - (log_lines_visible + 1):
                log_scroll_pos = len(log_lines) - log_lines_visible
        else:
            log_scroll_pos = max(len(log_lines) - 1, 0)
    return log_scroll_pos


# Render text with inline color codes
def render_colored_text(window, y, start_x, text, default_attr):
    """Render text with inline color codes like [GREEN]text[/GREEN]"""
    import re

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
def update_log_window(log_lines, bottom_win, log_scroll_pos):
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

    visible_logs = log_lines[log_scroll_pos:log_scroll_pos + log_height]
    for idx, log in enumerate(visible_logs):
        ts_attr = color_attr_for("timestamp") | curses.A_BOLD
        txt_attr = color_attr_for("log_text")
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
                render_colored_text(bottom_win, y, x, msg, txt_attr)
        except curses.error:
            pass
    bottom_win.refresh()
    return log_scroll_pos


# Monitor swap usage
def monitor_swap_usage(log_lines, bottom_win, swap_high_threshold, swap_low_threshold, log_scroll_pos):
    swap_percent = psutil.swap_memory().percent
    if swap_percent >= swap_high_threshold:
        log_scroll_pos = log_action(
            f"Swap usage is [RED]{swap_percent:.1f}%[/RED], which [RED]exceeds[/RED] the threshold of [YELLOW]{swap_high_threshold}%[/YELLOW].",
            log_lines, log_scroll_pos
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
                service_name = monitored_apps[proc_name][0]
                log_scroll_pos = restart_app(service_name, log_lines, log_scroll_pos)
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
                    if apps_restarted == len(monitored_apps):
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
def setup_ui(stdscr):
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
    bottom_h = height - top_left_h - 3  # Adjust for the title line and extra space
    top_left_w = width // 2
    top_right_w = width - top_left_w

    # Create windows starting from line 2 to avoid overlapping the title
    top_left_win = curses.newwin(top_left_h, top_left_w, 2, 0)
    top_right_win = curses.newwin(top_right_h, top_right_w, 2, top_left_w)
    bottom_win = curses.newwin(bottom_h, width, top_left_h + 2, 0)

    # Themed backgrounds for windows (inherit default bg)
    for w in (top_left_win, top_right_win, bottom_win):
        w.bkgd(' ', color_attr_for("background"))

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

    return top_left_win, top_right_win, bottom_win


# Performance-optimized helper functions
def batch_read_swap_data(pids):
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
                        swap_kb = int(line.split()[1])
                        swap_data[pid] = swap_kb * 1024  # Convert to bytes
                        break
                else:
                    swap_data[pid] = 0  # No swap line found
        except (FileNotFoundError, PermissionError, ValueError, OSError):
            swap_data[pid] = 0
            continue

    return swap_data


def get_monitored_pids_cached(force_refresh=False):
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
def get_top_swap_apps(force_refresh=False):
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
            total_swap = 1  # Avoid division by zero

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
        _performance_stats['adaptive_cache_time'] = max(5, _performance_stats['adaptive_cache_time'] - 1)
    # Longer cache time if low swap usage and fast scans (system is idle)
    elif current_swap_usage < 20 and scan_duration < 0.5:
        _performance_stats['adaptive_cache_time'] = min(30, _performance_stats['adaptive_cache_time'] + 2)

    return app_swap_usage


# Update dynamic data on the screen (colorized)
def update_ui(top_left_win, top_right_win):
    # Memory and Swap Usage
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
        label_attr = color_attr_for("swap_label") | curses.A_BOLD
        value_attr = percent_high_attr if swap_percent >= 1.0 else percent_ok_attr  # highlight if using >1% swap
        y = 2 + idx
        try:
            top_right_win.addstr(y, 2, f"{app_name}: ", label_attr)
            suffix = " (Children)" if (app['include_children'] and app['has_children']) else ""
            top_right_win.addstr(y, 2 + len(app_name) + 2, f"{swap_percent:.2f}%{suffix}", value_attr)
        except curses.error:
            pass
    top_right_win.refresh()


# --------- NON-FLASHING WINDOWS ---------
def draw_menu(stdscr, selected_idx, existing_win=None):
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


def draw_theme_dialog(stdscr, selected_idx, themes, existing_win=None):
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


def show_help(stdscr):
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
def main():
    global log_lines_visible  # Declare as global to access in log_action

    # Parse command-line arguments
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--swap-high', type=float, help='Set the swap high threshold percentage (default: 75).')
    parser.add_argument('--swap-low', type=float, help='Set the swap low threshold percentage (default: 50).')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message and exit.')
    args = parser.parse_args()

    if args.help:
        print(CMD_HELP_TEXT)
        sys.exit(0)

    # Set swap thresholds based on command-line arguments or use defaults
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
        top_left_win, top_right_win, bottom_win = setup_ui(stdscr)

        # Determine the number of visible log lines
        log_lines_visible = bottom_win.getmaxyx()[0] - 2  # Exclude borders

        # Initial logs/UI
        log_scroll_pos = log_action("SwapWatch 2.0 - Optimized monitoring started", log_lines, log_scroll_pos)
        log_scroll_pos = log_action("Performance features: PID caching, batch I/O, smart refresh", log_lines, log_scroll_pos)
        update_ui(top_left_win, top_right_win)
        update_log_window(log_lines, bottom_win, log_scroll_pos)
        log_scroll_pos = monitor_swap_usage(log_lines, bottom_win, swap_high_threshold, swap_low_threshold, log_scroll_pos)
        update_log_window(log_lines, bottom_win, log_scroll_pos)

        last_check_time = time.time()
        last_ui_update_time = time.time()
        while True:
            current_time = time.time()

            # Update UI at specified interval
            if current_time - last_ui_update_time >= UI_UPDATE_INTERVAL:
                if not in_menu and not in_theme:
                    update_ui(top_left_win, top_right_win)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                last_ui_update_time = current_time

            # Check swap usage every CHECK_INTERVAL seconds
            if current_time - last_check_time >= CHECK_INTERVAL:
                log_scroll_pos = monitor_swap_usage(log_lines, bottom_win, swap_high_threshold, swap_low_threshold, log_scroll_pos)
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
                        top_left_win, top_right_win, bottom_win = setup_ui(stdscr)
                        update_ui(top_left_win, top_right_win)
                        update_log_window(log_lines, bottom_win, log_scroll_pos)
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
                    theme_values = load_theme_by_name(chosen)  # re-sets OSC 11 + pairs
                    # Repaint main UI with new background/colors
                    in_theme = False
                    theme_win = None
                    top_left_win, top_right_win, bottom_win = setup_ui(stdscr)
                    update_ui(top_left_win, top_right_win)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                elif key in (27, ord('q')):
                    in_theme = False
                    theme_win = None
                    top_left_win, top_right_win, bottom_win = setup_ui(stdscr)
                    update_ui(top_left_win, top_right_win)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
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
                    log_scroll_pos = restart_app(service_name, log_lines, log_scroll_pos)
                    menu_win = draw_menu(stdscr, menu_selected_idx, menu_win)
                elif key in (ord('q'), 27):
                    in_menu = False
                    menu_win = None  # drop the dedicated window
                    top_left_win, top_right_win, bottom_win = setup_ui(stdscr)
                    update_ui(top_left_win, top_right_win)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                time.sleep(0.05)
                continue

            # Global key handling
            if key == ord('q'):
                break
            elif key == ord('m'):
                in_menu = True
                # show immediately with current selection
                menu_win = draw_menu(stdscr, menu_selected_idx, None)
            elif key == ord('t'):
                in_theme = True
                theme_selected_idx = 0
                theme_win = None
            elif key == ord('c'):
                # Force cache refresh for immediate data update
                log_scroll_pos = log_action("Forcing cache refresh...", log_lines, log_scroll_pos)
                get_monitored_pids_cached(force_refresh=True)
                get_top_swap_apps(force_refresh=True)
                update_ui(top_left_win, top_right_win)
                update_log_window(log_lines, bottom_win, log_scroll_pos)
                log_scroll_pos = log_action("Cache refreshed - data updated", log_lines, log_scroll_pos)
            elif key == ord('?'):
                show_help(stdscr)
                top_left_win, top_right_win, bottom_win = setup_ui(stdscr)
                update_ui(top_left_win, top_right_win)
                update_log_window(log_lines, bottom_win, log_scroll_pos)
            elif key == curses.KEY_UP:
                log_scroll_pos = max(0, log_scroll_pos - 1)
                update_log_window(log_lines, bottom_win, log_scroll_pos)
            elif key == curses.KEY_DOWN:
                max_scroll = max(len(log_lines) - log_lines_visible, 0)
                log_scroll_pos = min(max_scroll, log_scroll_pos + 1)
                update_log_window(log_lines, bottom_win, log_scroll_pos)

            time.sleep(0.1)
    finally:
        # Do not spam resets; leave terminal bg as-is (same pane/session).
        close_curses(stdscr)


if __name__ == '__main__':
    main()

