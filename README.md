# Threat Intelligence Fetch Script

## Overview

This Python script fetches threat intelligence data from specified URLs, filters out private IPs, and processes the data based on the content type. It supports CSV and JSON threat feed formats and provides real-time progress logging.

## Features

- **URL Validation:** Ensures that the provided URL has a valid scheme (http, https) and a valid network location.

- **Retry Mechanism:** Implements a retry mechanism using the `retry` library for fetching threat feeds, providing resilience against transient failures.

- **File Format Handling:** Dynamically determines the threat feed file format based on the content type in the response headers and parses the data accordingly.

- **Private IP Filtering:** Filters out private IP addresses from the threat data to enhance security.

- **Error Handling:** Catches and logs exceptions during the execution of critical functions, providing insights into potential issues.

- **Extensibility:** Designed to be extensible for adding additional threat feed formats or custom validation logic.


## Prerequisites

- Python 3.x
- Required Python packages: requests, pandas, retry

Install required packages using:

   ```bash
   pip install -r requirements.txt

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/shreyash2002/threat-intel-fetcher.git
   cd threat-intel-fetcher

2. Install dependencies

   ```bash 
   pip install -r requirements.txt

3. Run the script with predefined threat feed URLs

   ```bash 
   python threat_intel_fetch.py 

   Edit the predefined_threat_feed_urls list in the script for your specific use case.

4. Check the console output for the processed threat data. 

## Configuration 

The script can be configured by modifying the predefined threat feed URLs, output file name, and other parameters directly in the script.

##Contributing
If you'd like to contribute to the development of this script, please follow these steps:

Fork the repository.
Create a new branch for your feature or bug fix: git checkout -b feature/new-feature.
Commit your changes: git commit -m 'Add new feature'.
Push to the branch: git push origin feature/new-feature.
Submit a pull request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.