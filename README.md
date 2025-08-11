# ⏱️💾 SwapWatch 1.0

SwapWatch is a Python-based monitoring tool designed to keep an eye on your system's swap usage and take corrective actions when necessary. It provides a real-time, curses-based user interface that displays memory and swap usage, top memory-consuming applications, and logs of actions taken. SwapWatch helps prevent your system from becoming unresponsive due to high swap usage by automatically dropping caches and restarting services when thresholds are exceeded. The interface is fully themeable, allowing you to customize colors for a personalized look and better readability.


<img src="https://raw.githubusercontent.com/yodabytz/swapwatch/refs/heads/main/logo.png?raw=true" align="center" width="300">

## ✨ Features

- **Real-Time Monitoring**: Continuously monitors memory and swap usage to keep you informed of your system's performance.

- **Automated Actions**:
  - **Cache Management**: Automatically drops caches when swap usage exceeds defined thresholds.
  - **Service Management**: Restarts specified services that are consuming excessive memory to help reduce swap usage.

- **Curses-Based UI**:
  - **Terminal Interface**: Provides a terminal-based user interface displaying system metrics and logs in real-time.
  - **Interactive Menu**: Access an interactive menu to manually restart monitored services.
  - **Scrollable Logs**: Review past actions by scrolling through the logs directly within the UI.
  - **Help Menu**: Access a help screen by pressing `?`, displaying available commands and features.

- **Customizable Thresholds**:
  - **Command-Line Arguments**: Set high and low swap usage thresholds via command-line options:
    - `--swap-high VALUE`: Set the swap high threshold percentage (default: 75%).
    - `--swap-low VALUE`: Set the swap low threshold percentage (default: 50%).
  - **Validation**: Ensures that thresholds are within valid ranges and that the low threshold is less than the high threshold.

- **Service Management**:
  - **Automatic Restart**: Automatically restarts services based on their memory usage when swap usage remains high after dropping caches.
  - **Manual Control**: Use the interactive menu to manually restart monitored services at any time.

- **Process Memory Calculation**:
  - **Child Processes Inclusion**: Optionally include child processes in memory calculations for services like `nginx`.
  - **Accurate Memory Usage**: Uses RSS (Resident Set Size) for precise memory usage reporting, avoiding double-counting shared memory.

- **User Interaction**:
  - **Keyboard Controls**:
    - Press `m` to open the interactive menu.
    - Use the `Up` and `Down` arrow keys to navigate through logs and menus.
    - Press `r` to restart a selected service from the menu.
    - Press `q` to quit the application.
    - Press `?` to display the help menu.
    - 
- **Command-Line Help**:
  - **Usage Information**: Run `swapwatch.py -h` or `swapwatch.py --help` to display command-line options and usage examples.


## 📚Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Customization](#customization)
- [License](#license)

## 🛠 Requirements

- **Operating System**: Linux (with systemd)
- **Python Version**: Python 3.x
- **Python Modules**:
  - `psutil`
  - `curses` (usually included with Python)
  - `logging`
  - `subprocess`
  - `datetime`

## 📥 Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yodabytz/swapwatch.git
   cd swapwatch
   sudo mkdir -p /etc/swapwatch/themes/
   sudo cp *.themes /etc/swapwatch/themes/

   pip3 install psutil
   ```

## Monitored Applications
Edit the monitored_apps list in swapwatch.py to include the services you want SwapWatch to manage, i.e.:
```monitored_apps = [
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
```
## Swap Thresholds
Adjust the SWAP_HIGH_THRESHOLD and SWAP_LOW_THRESHOLD values as needed:
```SWAP_HIGH_THRESHOLD = 75  # Start taking action when swap usage exceeds 75%
SWAP_LOW_THRESHOLD = 50   # Target swap usage to achieve after actions
```
## Check Interval
Modify the CHECK_INTERVAL to set how often (in seconds) SwapWatch checks swap usage:

```
CHECK_INTERVAL = 300  # Check every 5 minutes
```
## Usage Instructions

1. **Make the script executable**:

   ```bash
   chmod +x swapwatch.py
## Run SwapWatch
```
sudo ./swapwatch.py
```

## SwapWatch Command-Line Options:
```
Usage:
  swapwatch.py [options]

Options:
  -h, --help            Show this help message and exit.
  --swap-high VALUE     Set the swap high threshold percentage (default: 75).
  --swap-low VALUE      Set the swap low threshold percentage (default: 50).

Example:
  swapwatch.py --swap-high 80 --swap-low 60
```
## Log File Location
The default log file is /var/log/swapwatch.log. Ensure the script has write permissions to this location or change the path:
```
LOG_FILE = "/var/log/swapwatch.log"
```

## License
SwapWatch is released under the MIT License.


