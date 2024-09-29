# SwapWatch 1.0

SwapWatch is a Python-based monitoring tool designed to keep an eye on your system's swap usage and take corrective actions when necessary. It provides a real-time curses-based user interface that displays memory and swap usage, top memory-consuming applications, and logs of actions taken. SwapWatch helps prevent your system from becoming unresponsive due to high swap usage by automatically dropping caches and restarting services when thresholds are exceeded.

## Features

- **Real-Time Monitoring**: Continuously monitors memory and swap usage.
- **Automated Actions**: Drops caches and restarts specified services when swap usage exceeds defined thresholds.
- **Curses-Based UI**: Provides a terminal-based user interface displaying system metrics and logs.
- **Customizable Thresholds**: Allows configuration of high and low swap usage thresholds.
- **Service Management**: Restarts services that are consuming excessive memory.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Customization](#customization)
- [License](#license)

## Requirements

- **Operating System**: Linux (with systemd)
- **Python Version**: Python 3.x
- **Python Modules**:
  - `psutil`
  - `curses` (usually included with Python)
  - `logging`
  - `subprocess`
  - `datetime`

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/swapwatch.git
   cd swapwatch

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
### Usage
Ensure Root Privileges

SwapWatch requires root privileges to restart services and drop caches. Run the script with sudo or as the root user.

# Run SwapWatch
```
sudo python3 swapwatch.py
```
## Log File Location
The default log file is /var/log/swapwatch.log. Ensure the script has write permissions to this location or change the path:
```
LOG_FILE = "/var/log/swapwatch.log"
```

## License
SwapWatch is released under the MIT License.


