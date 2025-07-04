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

# Logging setup
LOG_FILE = "/var/log/swapwatch.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',  # Logging module adds timestamp
    datefmt='%Y-%m-%d %H:%M:%S'
)


def apply_prlimit(pid, mem_limit_bytes):
    """Apply virtual memory limit to a process."""
    try:
        subprocess.run(["prlimit", "--pid", str(pid), "--as=" + str(mem_limit_bytes)], check=True)
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"Failed to apply prlimit to PID {pid}: {e}")
        return False


# Monitored applications mapping: process names to service names and include_children flag
# Specify which apps should include child processes
monitored_apps = {
    # process_name: (service_name, include_children)
    "clamd": ("clamav-daemon", False),
    "spamd": ("spamd", False),
    "dovecot": ("dovecot", False),
    "opendmarc": ("opendmarc", False),
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
    "nginx": ("nginx", True)  # Include nginx and combine child processes
}

# Default swap thresholds (can be overridden via command-line arguments)
SWAP_HIGH_THRESHOLD = 80  # Threshold to start taking action
SWAP_LOW_THRESHOLD = 65   # Target swap usage to achieve

# Check interval in seconds (5 minutes)
CHECK_INTERVAL = 300

# UI update interval in seconds
UI_UPDATE_INTERVAL = 1  # Update UI every 1 second

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
SwapWatch Help Menu
-------------------

Available Commands:
- 'q'       : Quit the application.
- 'm'       : Open the menu to select and restart monitored applications.
- '?'       : Display this help menu.
- Up/Down   : Scroll through logs or navigate menus.
- 'r'       : Restart selected service in the menu.
- 'Esc'     : Exit from the menu or help screen.

Features:
- Real-time monitoring of memory and swap usage.
- Automatic actions when swap usage exceeds thresholds.
- Scrollable logs to review past actions.
- Interactive menu to manually restart monitored services.
"""

# Initialize curses
def init_curses():
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    curses.curs_set(0)  # Hide the cursor
    stdscr.nodelay(True)  # Make getch non-blocking
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
        result = subprocess.run(
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
        subprocess.run(['sync'], check=True)
        with open('/proc/sys/vm/drop_caches', 'w') as f:
            f.write('3\n')
        log_scroll_pos = log_action("Dropped caches", log_lines, log_scroll_pos)
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
            # If log_lines_visible is not defined yet, set log_scroll_pos to 0
            log_scroll_pos = max(len(log_lines) - 1, 0)
    return log_scroll_pos

# Update the log window
def update_log_window(log_lines, bottom_win, log_scroll_pos):
    bottom_win.erase()
    bottom_win.box()
    bottom_win.addstr(0, 2, "Logs")  # Redraw the title
    log_height = bottom_win.getmaxyx()[0] - 2  # Exclude border
    total_logs = len(log_lines)
    visible_logs = log_lines[log_scroll_pos:log_scroll_pos + log_height]
    for idx, log in enumerate(visible_logs):
        # Ensure the log line fits within the window width
        max_width = bottom_win.getmaxyx()[1] - 2
        bottom_win.addstr(1 + idx, 1, log[:max_width])
    bottom_win.refresh()
    return log_scroll_pos

# Monitor swap usage
def monitor_swap_usage(log_lines, bottom_win, swap_high_threshold, swap_low_threshold, log_scroll_pos):
    swap_percent = psutil.swap_memory().percent
    if swap_percent >= swap_high_threshold:
        log_scroll_pos = log_action(f"Swap usage is {swap_percent}%, which exceeds the threshold of {swap_high_threshold}%.", log_lines, log_scroll_pos)
        log_scroll_pos = drop_caches(log_lines, log_scroll_pos)
        time.sleep(2)
        swap_percent = psutil.swap_memory().percent
        if swap_percent >= swap_low_threshold:
            log_scroll_pos = log_action(f"Swap usage still too high at {swap_percent}%, restarting services based on memory usage.", log_lines, log_scroll_pos)
            # Get applications sorted by memory usage
            top_apps = get_top_memory_apps()
            apps_restarted = 0
            for app in top_apps:
                proc_name = app['name']
                service_name = monitored_apps[proc_name][0]
                log_scroll_pos = restart_app(service_name, log_lines, log_scroll_pos)
                apps_restarted += 1
                time.sleep(2)
                swap_percent = psutil.swap_memory().percent
                if swap_percent < swap_low_threshold:
                    log_scroll_pos = log_action(f"Done! Usage now at {swap_percent}% which is below the threshold of {swap_low_threshold}%", log_lines, log_scroll_pos)
                    log_scroll_pos = log_action("Resuming normal operations", log_lines, log_scroll_pos)
                    break
                else:
                    if apps_restarted == len(monitored_apps):
                        log_scroll_pos = log_action(f"Done! Usage now at {swap_percent}% which is still not lower than {swap_low_threshold}%", log_lines, log_scroll_pos)
                        log_scroll_pos = log_action("Resuming normal operations", log_lines, log_scroll_pos)
                    else:
                        log_scroll_pos = log_action(f"Swap usage still high at {swap_percent}%, continuing to restart services.", log_lines, log_scroll_pos)
        else:
            log_scroll_pos = log_action(f"Swap usage is {swap_percent}%, which is now below the target of {swap_low_threshold}%.", log_lines, log_scroll_pos)
    else:
        log_scroll_pos = log_action(f"Swap usage is {swap_percent}%, which is below the threshold of {swap_high_threshold}%.", log_lines, log_scroll_pos)
    return log_scroll_pos

# Set up the UI
def setup_ui(stdscr):
    height, width = stdscr.getmaxyx()

    # Add the app name to the top of the screen
    title = "SwapWatch 1.0"
    stdscr.addstr(0, (width - len(title)) // 2, title, curses.A_BOLD)
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

    # Draw borders and titles
    top_left_win.box()
    top_left_win.addstr(0, 2, "Memory & Swap Usage")
    top_left_win.refresh()

    top_right_win.box()
    top_right_win.addstr(0, 2, "Top Apps by Memory Usage")
    top_right_win.refresh()

    bottom_win.box()
    bottom_win.addstr(0, 2, "Logs")
    bottom_win.refresh()

    return top_left_win, top_right_win, bottom_win

# Get top memory apps (FIXED FUNCTION)
def get_top_memory_apps():
    app_memory_usage = []
    monitored_process_names = list(monitored_apps.keys())
    total_physical_memory = psutil.virtual_memory().total
    app_memory = {}
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            proc_name = proc.info['name'] or ''
            exe = proc.info.get('exe') or ''
            cmdline = proc.info.get('cmdline') or []
            for mon_name in monitored_process_names:
                if (
                    mon_name in proc_name
                    or mon_name in exe
                    or any(mon_name in arg for arg in cmdline)
                ):
                    include_children = monitored_apps[mon_name][1]
                    total_rss = 0
                    has_children = False
                    try:
                        total_rss = proc.memory_info().rss
                        if include_children:
                            children = proc.children(recursive=True)
                            has_children = len(children) > 0
                            for child in children:
                                try:
                                    total_rss += child.memory_info().rss
                                except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError, ProcessLookupError):
                                    continue
                    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError, ProcessLookupError):
                        continue

                    if mon_name in app_memory:
                        app_memory[mon_name]['rss'] += total_rss
                        app_memory[mon_name]['has_children'] = app_memory[mon_name]['has_children'] or has_children
                    else:
                        app_memory[mon_name] = {
                            'name': mon_name,
                            'rss': total_rss,
                            'include_children': include_children,
                            'has_children': has_children
                        }
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError, ProcessLookupError):
            continue
    # Now calculate memory_percent for each app
    for app in app_memory.values():
        mem_percent = (app['rss'] / total_physical_memory) * 100
        app['memory_percent'] = mem_percent
    # Convert to a list and sort
    app_memory_usage = list(app_memory.values())
    app_memory_usage.sort(key=lambda x: x['memory_percent'], reverse=True)
    return app_memory_usage

# Update dynamic data on the screen
def update_ui(top_left_win, top_right_win):
    # Memory and Swap Usage
    mem_usage, swap_usage = get_memory_and_swap_usage()

    # Redraw the border and title
    top_left_win.box()
    top_left_win.addstr(0, 2, "Memory & Swap Usage")

    # Update only the usage lines without clearing the entire window
    top_left_win.addstr(2, 2, f"Memory Usage: {mem_usage:.2f}%    ")
    top_left_win.addstr(3, 2, f"Swap Usage: {swap_usage:.2f}%     ")
    top_left_win.refresh()

    # Top apps by memory usage
    top_apps = get_top_memory_apps()[:3]  # Get top 3 apps

    # Redraw the border and title
    top_right_win.box()
    top_right_win.addstr(0, 2, "Top Apps by Memory Usage")

    # Clear only the area where app data is displayed
    for idx in range(3):
        # Overwrite previous data with spaces
        top_right_win.addstr(2 + idx, 2, " " * (top_right_win.getmaxyx()[1] - 4))
    for idx, app in enumerate(top_apps):
        app_name = app['name']
        mem_percent = app['memory_percent']
        if app['include_children'] and app['has_children']:
            app_name_display = f"{app_name}: {mem_percent:.2f}% (Children)"
        else:
            app_name_display = f"{app_name}: {mem_percent:.2f}%"
        top_right_win.addstr(2 + idx, 2, app_name_display)
    top_right_win.refresh()

# Function to draw the menu
def draw_menu(stdscr, selected_idx):
    # Clear the screen and refresh
    stdscr.clear()
    stdscr.refresh()
    height, width = stdscr.getmaxyx()
    menu_win = curses.newwin(height, width, 0, 0)
    menu_win.box()
    header = "Monitored Applications (Press 'r' to restart, 'q' or Esc to exit menu)"
    menu_win.addstr(0, (width - len(header)) // 2, header)
    apps = list(monitored_apps.keys())
    max_items = height - 4  # Adjust for borders and header

    # Ensure selected_idx is within the bounds
    if selected_idx < 0:
        selected_idx = 0
    elif selected_idx >= len(apps):
        selected_idx = len(apps) - 1

    # Calculate start and end indices for the visible portion of the menu
    if len(apps) <= max_items:
        start_idx = 0
        end_idx = len(apps)
    else:
        if selected_idx < max_items // 2:
            start_idx = 0
        elif selected_idx > len(apps) - max_items // 2:
            start_idx = len(apps) - max_items
        else:
            start_idx = selected_idx - max_items // 2
        end_idx = start_idx + max_items

    display_apps = apps[start_idx:end_idx]
    for idx, app_name in enumerate(display_apps):
        line_num = 2 + idx
        try:
            if start_idx + idx == selected_idx:
                menu_win.attron(curses.A_REVERSE)
                menu_win.addstr(line_num, 2, app_name)
                menu_win.attroff(curses.A_REVERSE)
            else:
                menu_win.addstr(line_num, 2, app_name)
        except curses.error:
            pass  # Ignore errors when writing outside the window bounds
    menu_win.refresh()

# Function to display help menu
def show_help(stdscr):
    stdscr.clear()
    stdscr.refresh()
    height, width = stdscr.getmaxyx()
    help_win = curses.newwin(height, width, 0, 0)
    help_win.box()
    lines = APP_HELP_TEXT.strip().split('\n')
    for idx, line in enumerate(lines):
        try:
            help_win.addstr(1 + idx, 2, line)
        except curses.error:
            pass  # Ignore errors when writing outside the window bounds
    help_win.refresh()
    while True:
        key = stdscr.getch()
        if key == ord('q') or key == 27:  # Press 'q' or Esc to exit help
            break
        time.sleep(0.1)
    stdscr.clear()
    stdscr.refresh()

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

    stdscr = init_curses()
    log_lines = []
    log_scroll_pos = 0  # For scrolling the log window
    in_menu = False     # Flag to indicate if we are in the menu
    menu_selected_idx = 0  # Index of the selected menu item

    try:
        top_left_win, top_right_win, bottom_win = setup_ui(stdscr)

        # Determine the number of visible log lines
        log_lines_visible = bottom_win.getmaxyx()[0] - 2  # Exclude borders

        # Call log_action() after log_lines_visible is defined
        log_scroll_pos = log_action("Monitoring Started", log_lines, log_scroll_pos)

        # Call update_ui() immediately to display data at startup
        update_ui(top_left_win, top_right_win)
        update_log_window(log_lines, bottom_win, log_scroll_pos)  # Refresh the log window immediately

        # Call monitor_swap_usage() immediately to populate logs
        log_scroll_pos = monitor_swap_usage(log_lines, bottom_win, swap_high_threshold, swap_low_threshold, log_scroll_pos)
        update_log_window(log_lines, bottom_win, log_scroll_pos)

        last_check_time = time.time()
        last_ui_update_time = time.time()
        while True:
            current_time = time.time()

            # Update UI at specified interval
            if current_time - last_ui_update_time >= UI_UPDATE_INTERVAL:
                if not in_menu:
                    update_ui(top_left_win, top_right_win)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                last_ui_update_time = current_time

            # Check swap usage every CHECK_INTERVAL seconds
            if current_time - last_check_time >= CHECK_INTERVAL:
                log_scroll_pos = monitor_swap_usage(log_lines, bottom_win, swap_high_threshold, swap_low_threshold, log_scroll_pos)
                last_check_time = current_time

            # Handle user input
            key = stdscr.getch()
            if in_menu:
                if key == curses.KEY_UP:
                    menu_selected_idx = max(0, menu_selected_idx - 1)
                    draw_menu(stdscr, menu_selected_idx)
                elif key == curses.KEY_DOWN:
                    menu_selected_idx = min(len(monitored_apps) - 1, menu_selected_idx + 1)
                    draw_menu(stdscr, menu_selected_idx)
                elif key == ord('r'):
                    # Restart selected service
                    proc_name = list(monitored_apps.keys())[menu_selected_idx]
                    service_name = monitored_apps[proc_name][0]
                    log_scroll_pos = restart_app(service_name, log_lines, log_scroll_pos)
                    draw_menu(stdscr, menu_selected_idx)
                elif key == ord('q') or key == 27:  # Escape key
                    in_menu = False
                    stdscr.clear()
                    stdscr.refresh()
                    top_left_win, top_right_win, bottom_win = setup_ui(stdscr)
                    update_ui(top_left_win, top_right_win)
                    update_log_window(log_lines, bottom_win, log_scroll_pos)
                continue  # Skip the rest of the loop when in menu

            if key == ord('q'):
                break
            elif key == ord('m'):
                in_menu = True
                menu_selected_idx = 0
                draw_menu(stdscr, menu_selected_idx)
            elif key == ord('?'):
                show_help(stdscr)
                # After help screen, redraw the UI
                stdscr.clear()
                stdscr.refresh()
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

            # Short sleep to prevent high CPU usage
            time.sleep(0.1)
    finally:
        close_curses(stdscr)


if __name__ == '__main__':
    main()
