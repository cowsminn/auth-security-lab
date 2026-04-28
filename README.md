# Authentication & Security Lab

A hands-on project demonstrating common web security vulnerabilities and their mitigation. This lab contrasts a vulnerable implementation (`v1`) with a secure one (`v2`).

## Overview

This project provides a practical demonstration of fixing a critical security flaw. It is structured into two versions:

-   **`v1`**: A version with a direct SQL injection vulnerability, showing how improper query construction can be exploited.
-   **`v2`**: A refactored version that uses prepared statements to prevent SQL injection, demonstrating a secure way to handle database queries.

The goal is to provide a clear, hands-on example for developers to understand and prevent common security risks.

## System Architecture

The system architecture is straightforward, consisting of a Python backend that interacts with a SQLite database. The key difference between `v1` and `v2` lies in how the database queries are handled.

## Core Technologies

| Category | Technology | Purpose |
| --- | --- | --- |
| **Language** | Python | Backend logic |
| **Database** | SQLite | Data storage |
| **Interaction** | Command-Line | User input for login |

### Python Dependencies

This project uses Flask.

### Setup

1.  **Create a virtual environment:**

    ```bash
    python3 -m venv venv
    ```

2.  **Activate the virtual environment:**

    -   On Windows:

        ```bash
        venv\Scripts\activate
        ```

    -   On macOS and Linux:

        ```bash
        source venv/bin/activate
        ```

3.  **Install dependencies:**

    ```bash
    pip install flask
    ```
## Video Demonstration

[![demo](https://img.youtube.com/vi/eUc5V2GvTuY/0.jpg)](https://youtu.be/eUc5V2GvTuY)

## Limitations

1.  **Scope**: This lab focuses solely on SQL injection and does not cover other vulnerabilities.
2.  **Simplicity**: The application is intentionally minimal to keep the focus on the security concept.
3.  **Environment**: It is a command-line application and does not simulate a full web environment (e.g., no session management, hashing, etc.).

## Resources

-   [OWASP Top 10: Injection](https://owasp.org/Top10/A03_2021-Injection/)
-   [Python `sqlite3` documentation](https://docs.python.org/3/library/sqlite3.html)
-   [Real Python: Preventing SQL Injection in Python](https://realpython.com/prevent-python-sql-injection/)
