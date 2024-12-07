import re
import csv
from collections import Counter
from tabulate import tabulate


class LogReader:
    """Handles reading the log file."""

    def __init__(self, log_file_path):
        self.log_file_path = log_file_path

    def read_lines(self):
        """Generator to read the log file line by line."""
        try:
            with open(self.log_file_path, 'r') as file:
                for line in file:
                    yield line
        except FileNotFoundError:
            print(f"Error: Log file '{self.log_file_path}' not found.")
            raise
        except PermissionError:
            print(f"Error: Insufficient permissions to read '{self.log_file_path}'.")
            raise


class LogAnalyzer:
    """Analyzes log data for various metrics."""

    def __init__(self, log_reader):
        self.log_reader = log_reader
        self.ip_counter = Counter()
        self.endpoint_counter = Counter()
        self.failed_login_attempts = Counter()
        self.total_requests = 0

    def analyze_ip_requests(self):
        """Count the number of requests per IP address."""
        try:
            for line in self.log_reader.read_lines():
                self.total_requests += 1
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip_address = ip_match.group(1)
                    self.ip_counter[ip_address] += 1
        except Exception as e:
            print(f"Error while analyzing IP requests: {e}")

    def analyze_endpoints(self):
        """Find and count accessed endpoints."""
        try:
            for line in self.log_reader.read_lines():
                endpoint_match = re.search(r'"[A-Z]+\s(\/\S*)\s', line)
                if endpoint_match:
                    endpoint = endpoint_match.group(1)
                    self.endpoint_counter[endpoint] += 1
        except Exception as e:
            print(f"Error while analyzing endpoints: {e}")

    def detect_suspicious_activity(self, threshold=10):
        """
        Detect IPs with failed login attempts above a threshold.

        Args:
            threshold (int): Minimum failed attempts to be flagged as suspicious.
        """
        try:
            for line in self.log_reader.read_lines():
                if '401' in line or 'Invalid credentials' in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip_address = ip_match.group(1)
                        self.failed_login_attempts[ip_address] += 1
        except Exception as e:
            print(f"Error while detecting suspicious activity: {e}")


class LogReport:
    """Handles displaying and saving analysis results."""

    @staticmethod
    def display_ip_request_counts(ip_counter):
        """Display IP addresses and their request counts in a table format."""
        try:
            print("Task 1: IP Request Counts")
            table_data = [[ip, count] for ip, count in ip_counter.most_common()]
            headers = ["IP Address", "Request Count"]
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
        except Exception as e:
            print(f"Error while displaying IP request counts: {e}")

    @staticmethod
    def display_most_frequent_endpoint(endpoint_counter):
        """Display the most frequently accessed endpoint."""
        try:
            if endpoint_counter:
                most_common_endpoint, count = endpoint_counter.most_common(1)[0]
                print("\nTask 2: Most Frequently Accessed Endpoint")
                print(f"Endpoint: {most_common_endpoint} (Accessed {count} times)")
            else:
                print("\nTask 2: No endpoints found in the log file.")
        except Exception as e:
            print(f"Error while displaying the most frequent endpoint: {e}")

    @staticmethod
    def display_suspicious_activity(failed_login_attempts, threshold):
        """
        Display IPs with failed login attempts above a threshold.

        Args:
            failed_login_attempts (Counter): Failed login attempts by IP.
            threshold (int): Minimum failed attempts to display.
        """
        try:
            print("\nTask 3: Suspicious Activity Detected")
            table_data = [
                [ip, count]
                for ip, count in failed_login_attempts.items()
                if count > threshold
            ]
            if table_data:
                headers = ["IP Address", "Failed Login Attempts"]
                print(tabulate(table_data, headers=headers, tablefmt="grid"))
            else:
                print("No suspicious activity detected.")
        except Exception as e:
            print(f"Error while displaying suspicious activity: {e}")

    @staticmethod
    def save_results_to_csv(ip_counter, endpoint_counter, failed_login_attempts,
                            output_file='log_analysis_results.csv'):
        """
        Save analyzed results to a CSV file.

        Args:
            ip_counter (Counter): Request counts by IP.
            endpoint_counter (Counter): Accessed endpoints and counts.
            failed_login_attempts (Counter): Failed login attempts by IP.
            output_file (str): Name of the output CSV file.
        """
        try:
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)

                writer.writerow(["Requests per IP"])
                writer.writerow(["IP Address", "Request Count"])
                for ip, count in ip_counter.most_common():
                    writer.writerow([ip, count])
                writer.writerow([])

                if endpoint_counter:
                    most_common_endpoint, count = endpoint_counter.most_common(1)[0]
                    writer.writerow(["Most Accessed Endpoint"])
                    writer.writerow(["Endpoint", "Access Count"])
                    writer.writerow([most_common_endpoint, count])
                writer.writerow([])

                writer.writerow(["Suspicious Activity"])
                writer.writerow(["IP Address", "Failed Login Count"])
                for ip, count in failed_login_attempts.items():
                    writer.writerow([ip, count])

            print(f"\nResults saved to {output_file}")
        except Exception as e:
            print(f"Error while saving results to CSV: {e}")


def main():
    log_file_path = 'sample.log'  # Replace with your log file path

    try:
        # Modular instantiation
        log_reader = LogReader(log_file_path)
        analyzer = LogAnalyzer(log_reader)
        report = LogReport()

        # Task 1: Analyze and display IP request counts
        analyzer.analyze_ip_requests()
        report.display_ip_request_counts(analyzer.ip_counter)

        # Task 2: Analyze and display the most frequently accessed endpoint
        analyzer.analyze_endpoints()
        report.display_most_frequent_endpoint(analyzer.endpoint_counter)

        # Task 3: Detect and display suspicious activity
        analyzer.detect_suspicious_activity(threshold=10)
        report.display_suspicious_activity(analyzer.failed_login_attempts, threshold=5)

        # Save results to CSV
        report.save_results_to_csv(
            analyzer.ip_counter,
            analyzer.endpoint_counter,
            analyzer.failed_login_attempts
        )
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
