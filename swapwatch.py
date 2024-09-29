import curses
import psutil
import time
import os
import logging
from datetime import datetime
import subprocess
import sys

# Logging setup
LOG_FILE = "/var/log/swapwatch.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',  # Logging module adds timestamp
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Monitored applications array (ensure service names match systemctl service names)
monitored_apps = [
    "clamav-daemon",
    "spamd",
    "dovecot",
    "opendmarc",
    "kiwiirc",
    "amavis",
    "postfix",
    "webmin",
    "monitorix",
    "php8.2-fpm",
    "php8.3-fpm",
    "mariadb"
]

# Swap thresholds
SWAP_HIGH_THRESHOLD = 75  # Threshold to start taking action
SWAP_LOW_THRESHOLD = 50   # Target swap usage to achieve

# Check interval in seconds (5 minutes)
CHECK_INTERVAL = 300

# UI update interval in seconds
UI_UPDATE_INTERVAL = 1  # Update UI every 1 second

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
def restart_app(app_name, log_lines):
    try:
        log_action(f"Restarting service {app_name}", log_lines)
        result = subprocess.run(
            ['systemctl', 'restart', app_name],
            check=True,
            timeout=60,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        log_action(f"Service {app_name} restarted successfully.", log_lines)
    except subprocess.TimeoutExpired:
        log_action(f"Restarting {app_name} timed out.", log_lines)
    except subprocess.CalledProcessError as e:
        log_action(f"Failed to restart {app_name}: {e.stderr.strip()}", log_lines)
    except Exception as e:
        log_action(f"Unexpected error restarting {app_name}: {e}", log_lines)

# Drop caches
def drop_caches(log_lines):
    try:
        subprocess.run(['sync'], check=True)
        with open('/proc/sys/vm/drop_caches', 'w') as f:
            f.write('3\n')
        log_action("Dropped caches", log_lines)
    except Exception as e:
        log_action(f"Failed to drop caches: {e}", log_lines)

# Log actions
def log_action(action, log_lines):
    # For curses app display, add timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    display_message = f"{timestamp} - {action}"
    # For log file, let logging module handle the timestamp
    logging.info(action)
    if log_lines is not None:
        log_lines.append(display_message)
    # Do not call update_log_window() here

# Update the log window
def update_log_window(log_lines, bottom_win):
    # Only update the new log lines
    bottom_win.erase()
    bottom_win.box()
    bottom_win.addstr(0, 2, "Logs")  # Redraw the title
    log_height = bottom_win.getmaxyx()[0] - 2  # Exclude border
    visible_logs = log_lines[-log_height:]
    for idx, log in enumerate(visible_logs):
        # Ensure the log line fits within the window width
        max_width = bottom_win.getmaxyx()[1] - 2
        bottom_win.addstr(1 + idx, 1, log[:max_width])
    bottom_win.refresh()

# Monitor swap usage
def monitor_swap_usage(log_lines, bottom_win):
    swap_percent = psutil.swap_memory().percent
    if swap_percent >= SWAP_HIGH_THRESHOLD:
        log_action(f"Swap usage is {swap_percent}%, which exceeds the threshold of {SWAP_HIGH_THRESHOLD}%.", log_lines)
        drop_caches(log_lines)
        time.sleep(2)
        swap_percent = psutil.swap_memory().percent
        if swap_percent >= SWAP_LOW_THRESHOLD:
            log_action(f"Swap usage still too high at {swap_percent}%, restarting services.", log_lines)
            apps_restarted = 0
            for app_name in monitored_apps:
                restart_app(app_name, log_lines)
                apps_restarted += 1
                time.sleep(2)
                swap_percent = psutil.swap_memory().percent
                if swap_percent < SWAP_LOW_THRESHOLD:
                    log_action(f"Done! Usage now at {swap_percent}% which is below the threshold of {SWAP_LOW_THRESHOLD}%", log_lines)
                    log_action("Resuming normal operations", log_lines)
                    break
                else:
                    if apps_restarted == len(monitored_apps):
                        log_action(f"Done! Usage now at {swap_percent}% which is still not lower than {SWAP_LOW_THRESHOLD}%", log_lines)
                        log_action("Resuming normal operations", log_lines)
                    else:
                        log_action(f"Done! Usage now at {swap_percent}% but still too high", log_lines)
        else:
            log_action(f"Swap usage is {swap_percent}%, which is now below the target of {SWAP_LOW_THRESHOLD}%.", log_lines)
    else:
        log_action(f"Swap usage is {swap_percent}%, which is below the threshold of {SWAP_HIGH_THRESHOLD}%.", log_lines)

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

    # Create windows starting from line 1 to avoid overlapping the title
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

# Update dynamic data on the screen
def update_ui(top_left_win, top_right_win):
    # Memory and Swap Usage
    mem_usage, swap_usage = get_memory_and_swap_usage()

    # Redraw the border and title
    top_left_win.box()
    top_left_win.addstr(0, 2, "Memory & Swap Usage")

    # Update only the usage lines without clearing the entire window
    top_left_win.addstr(2, 2, f"Memory Usage: {mem_usage}%    ")
    top_left_win.addstr(3, 2, f"Swap Usage: {swap_usage}%     ")
    top_left_win.refresh()

    # Top 3 apps by memory usage
    top_apps = get_top_memory_apps()[:3]  # Get top 3 apps

    # Redraw the border and title
    top_right_win.box()
    top_right_win.addstr(0, 2, "Top Apps by Memory Usage")

    # Clear only the area where app data is displayed
    for idx in range(3):
        # Overwrite previous data with spaces
        top_right_win.addstr(2 + idx, 2, " " * (top_right_win.getmaxyx()[1] - 4))
    for idx, app in enumerate(top_apps):
        app_name = app.info['name']
        mem_percent = app.info['memory_percent']
        top_right_win.addstr(2 + idx, 2, f"{app_name}: {mem_percent:.2f}%")
    top_right_win.refresh()

# Get top memory apps (all monitored apps)
def get_top_memory_apps():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
        if proc.info['name'] in monitored_apps:
            processes.append(proc)
    processes.sort(key=lambda p: p.info['memory_percent'], reverse=True)
    return processes

# Run the curses app
def main():
    # Ensure the script is run as root
    if os.geteuid() != 0:
        print("This script must be run as root to function properly.")
        sys.exit(1)

    stdscr = init_curses()
    log_lines = []

    try:
        top_left_win, top_right_win, bottom_win = setup_ui(stdscr)
        log_action("Monitoring Started", log_lines)

        # Call update_ui() immediately to display data at startup
        update_ui(top_left_win, top_right_win)
        update_log_window(log_lines, bottom_win)  # Refresh the log window immediately

        # Call monitor_swap_usage() immediately to populate logs
        monitor_swap_usage(log_lines, bottom_win)

        last_check_time = time.time()
        last_ui_update_time = time.time()
        while True:
            current_time = time.time()

            # Update UI at specified interval
            if current_time - last_ui_update_time >= UI_UPDATE_INTERVAL:
                update_ui(top_left_win, top_right_win)
                update_log_window(log_lines, bottom_win)
                last_ui_update_time = current_time

            # Check swap usage every CHECK_INTERVAL seconds
            if current_time - last_check_time >= CHECK_INTERVAL:
                monitor_swap_usage(log_lines, bottom_win)
                last_check_time = current_time

            # Check for 'q' key press to quit the app
            key = stdscr.getch()
            if key == ord('q'):
                break

            # Short sleep to prevent high CPU usage
            time.sleep(0.1)
    finally:
        close_curses(stdscr)

if __name__ == '__main__':
    main()
