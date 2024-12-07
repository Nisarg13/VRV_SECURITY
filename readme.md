
---

# Log Analyzer

## Overview
The **Log Analyzer** is a Python-based tool designed to analyze server log files and generate meaningful insights, such as:
- Counting the number of requests per IP address.
- Identifying the most frequently accessed endpoints.
- Detecting suspicious activity based on failed login attempts.

The tool also provides options to display results in a user-friendly tabular format and save them to a CSV file for further analysis.

---

## Features
1. **IP Request Analysis**:
   - Counts the number of requests made by each IP address.
   - Displays results in a formatted table.

2. **Endpoint Analysis**:
   - Identifies the most frequently accessed endpoints (e.g., URLs or resources).

3. **Suspicious Activity Detection**:
   - Detects IP addresses with failed login attempts above a configurable threshold.
   - Displays suspicious IPs along with their failed login counts.

4. **CSV Export**:
   - Saves the results (IP requests, endpoints, suspicious activities) to a CSV file for offline analysis.

---

## Prerequisites
- Python 3.6 or higher

### Required Libraries
The script uses the following Python libraries:
- `re` (Regular Expressions) – for parsing log files.
- `csv` – for saving results to a CSV file.
- `collections.Counter` – for counting occurrences.
- `tabulate` – for generating user-friendly tables.

Install the required library using pip:
```bash
pip install tabulate
```

---

## Usage

1. Clone this repository or download the script.
2. Place your log file in the same directory as the script.
3. Edit the `log_file_path` variable in the `main()` function to point to your log file.
4. Run the script:
   ```bash
   python log_analyzer.py
   ```

---

## Modular Structure

### 1. LogReader
- **Purpose**: Handles file reading.
- **Key Method**: 
  - `read_lines()` – Reads the log file line by line.

### 2. LogAnalyzer
- **Purpose**: Analyzes log data for various metrics.
- **Key Methods**:
  - `analyze_ip_requests()` – Counts requests per IP.
  - `analyze_endpoints()` – Identifies accessed endpoints.
  - `detect_suspicious_activity(threshold)` – Flags IPs with failed login attempts above a threshold.

### 3. LogReport
- **Purpose**: Handles displaying and saving analysis results.
- **Key Methods**:
  - `display_ip_request_counts(ip_counter)` – Displays IP request counts in a table.
  - `display_most_frequent_endpoint(endpoint_counter)` – Displays the most accessed endpoint.
  - `display_suspicious_activity(failed_login_attempts, threshold)` – Displays suspicious activities.
  - `save_results_to_csv(ip_counter, endpoint_counter, failed_login_attempts, output_file)` – Saves results to a CSV file.

---

## Output

### Console
The results are displayed in tabular format for easy visualization, using the `tabulate` library.

### CSV File
Results are saved to a file named `log_analysis_results.csv` (default). The file includes:
- Requests per IP.
- The most accessed endpoint.
- Suspicious activities (if any).

---

## Configuration
You can customize the following in the `main()` function:
1. **Log file path**:
   ```python
   log_file_path = 'your_log_file.log'
   ```
2. **Threshold for suspicious activity detection**:
   ```python
   analyzer.detect_suspicious_activity(threshold=10)
   ```

---

## Example
Sample log file (`sample.log`):
```
127.0.0.1 - - [07/Dec/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024
127.0.0.1 - - [07/Dec/2024:12:01:00 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.1 - - [07/Dec/2024:12:02:00 +0000] "GET /dashboard HTTP/1.1" 200 2048
```

Sample output in the console:
```
Task 1: IP Request Counts
+---------------+---------------+
| IP Address    | Request Count |
+===============+===============+
| 127.0.0.1     | 2             |
| 192.168.1.1   | 1             |
+---------------+---------------+

Task 2: Most Frequently Accessed Endpoint
Endpoint: /index.html (Accessed 1 times)

Task 3: Suspicious Activity Detected
+---------------+-----------------------+
| IP Address    | Failed Login Attempts |
+===============+=======================+
| 127.0.0.1     | 1                     |
+---------------+-----------------------+
```

---


## Author
**Nisarg Ganatra**  
Machine Learning Researcher and Software Developer

Feel free to connect on [LinkedIn](https://www.linkedin.com/in/nisarg-ganatra-5330391b5/).