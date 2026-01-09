<div id="top">

<!-- HEADER STYLE: CLASSIC -->
<div align="center">


# MULTI-SERVICES-HONEYPOT-

<em>Unleash Deception, Detect Threats, Secure Your Future</em>

<!-- BADGES -->
<img src="https://img.shields.io/github/last-commit/Lak-MedRida027/Multi-Services-Honeypot-?style=flat&logo=git&logoColor=white&color=0080ff" alt="last-commit">
<img src="https://img.shields.io/github/languages/top/Lak-MedRida027/Multi-Services-Honeypot-?style=flat&color=0080ff" alt="repo-top-language">
<img src="https://img.shields.io/github/languages/count/Lak-MedRida027/Multi-Services-Honeypot-?style=flat&color=0080ff" alt="repo-language-count">

<em>Built with the tools and technologies:</em>

<img src="https://img.shields.io/badge/Flask-000000.svg?style=flat&logo=Flask&logoColor=white" alt="Flask">
<img src="https://img.shields.io/badge/Python-3776AB.svg?style=flat&logo=Python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Socket-C93CD7.svg?style=flat&logo=Socket&logoColor=white" alt="Socket">

</div>
<br>

<img src="[./images/logo.png](https://ibb.co/5gRWd34f)" alt="Logo" width="200" height="100" align="center">

---

## Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Usage](#usage)
    - [Testing](#testing)
- [Features](#features)
- [Project Structure](#project-structure)
    - [Project Index](#project-index)
- [Acknowledgment](#acknowledgment)

---

## Overview

Multi-Services-Honeypot is a powerful, modular framework that deploys multiple decoy services—such as SSH, HTTP, MySQL, and RDP—to simulate real-world attack scenarios. It enables security researchers and developers to monitor, log, and analyze malicious activity across various protocols in a unified environment.

**Why Multi-Services-Honeypot?**

This project helps you create a comprehensive security research environment. The core features include:

- **🛡️ Multi-Protocol Simulation:** Orchestrates diverse honeypots to mimic real services and attract attackers.
- **🔧 Modular Architecture:** Easily extend or customize individual honeypot modules for specific research needs.
- **📝 Centralized Logging:** Captures detailed attacker interactions for analysis and threat intelligence.
- **🚀 Easy Deployment:** Command-line interface simplifies configuration and launch of multiple honeypots.
- **🔄 Concurrent Management:** Handles simultaneous service execution with graceful shutdown capabilities.
- **⚙️ Configurable Environment:** Centralized settings ensure consistent deployment across distributed modules.

---

## Features

|      | Component       | Details                                                                                     |
| :--- | :-------------- | :------------------------------------------------------------------------------------------ |
| ⚙️  | **Architecture**  | <ul><li>Modular design separating honeypot services (e.g., SSH, HTTP, FTP)</li><li>Event-driven with asyncio for concurrency</li><li>Client-server model for interaction logging</li></ul> |
| 🔩 | **Code Quality**  | <ul><li>Clear structure with dedicated modules</li><li>Consistent naming conventions</li><li>Uses standard Python practices</li></ul> |
| 📄 | **Documentation** | <ul><li>Basic README with project overview</li><li>Comments within code, but lacks comprehensive docs</li></ul> |
| 🔌 | **Integrations**  | <ul><li>Flask for web interface or API endpoints</li><li>Paramiko for SSH interactions</li><li>MySQL connector for data storage</li><li>pyrdp for RDP protocol simulation</li></ul> |
| 🧩 | **Modularity**    | <ul><li>Separate modules for each honeypot service</li><li>Reusable components for network handling</li></ul> |
| 🧪 | **Testing**       | <ul><li>Minimal or no explicit testing framework indicated</li><li>Potential for unit tests in modules</li></ul> |
| ⚡️  | **Performance**   | <ul><li>Uses asyncio for concurrent handling of multiple connections</li><li>Lightweight, minimal blocking operations</li></ul> |
| 🛡️ | **Security**      | <ul><li>Basic logging of interactions</li><li>Potential exposure if deployed publicly; lacks advanced security measures</li></ul> |
| 📦 | **Dependencies**  | <ul><li>Relies on `requirements.txt` for package management</li><li>Key dependencies include Flask, paramiko, mysql-connector-python, pyrdp, asyncio</li></ul> |

---

## Project Structure

```sh
└── Multi-Services-Honeypot-/
    ├── config
    │   └── settings.py
    ├── honeypot
    │   ├── __init__.py
    │   ├── cli.py
    │   ├── http_honeypot.py
    │   ├── logger.py
    │   ├── mysql_honeypot.py
    │   ├── rdp_honeypot.py
    │   └── ssh_honeypot.py
    ├── images
    │   └── logo.png
    ├── main.py
    └── requirements.txt
```

---

### Project Index

<details open>
	<summary><b><code>MULTI-SERVICES-HONEYPOT-/</code></b></summary>
	<!-- __root__ Submodule -->
	<details>
		<summary><b>__root__</b></summary>
		<blockquote>
			<div class='directory-path' style='padding: 8px 0; color: #666;'>
				<code><b>⦿ __root__</b></code>
			<table style='width: 100%; border-collapse: collapse;'>
			<thead>
				<tr style='background-color: #f8f9fa;'>
					<th style='width: 30%; text-align: left; padding: 8px;'>File Name</th>
					<th style='text-align: left; padding: 8px;'>Summary</th>
				</tr>
			</thead>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='https://github.com/Lak-MedRida027/Multi-Services-Honeypot-/blob/master/main.py'>main.py</a></b></td>
					<td style='padding: 8px;'>- Orchestrates the deployment of multiple honeypot services based on user input, enabling comprehensive simulation of various attack vectors such as SSH, HTTP, MySQL, and RDP<br>- Manages concurrent execution, logging, and graceful shutdown, forming the core control point that integrates individual honeypot modules into a cohesive security research environment.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='https://github.com/Lak-MedRida027/Multi-Services-Honeypot-/blob/master/requirements.txt'>requirements.txt</a></b></td>
					<td style='padding: 8px;'>- Defines project dependencies essential for secure remote communication, web server functionality, and database connectivity<br>- Ensures consistent environment setup for components handling SSH, web interactions, terminal emulation, and data storage, supporting the overall architectures seamless operation and integration across distributed modules.</td>
				</tr>
			</table>
		</blockquote>
	</details>
	<!-- honeypot Submodule -->
	<details>
		<summary><b>honeypot</b></summary>
		<blockquote>
			<div class='directory-path' style='padding: 8px 0; color: #666;'>
				<code><b>⦿ honeypot</b></code>
			<table style='width: 100%; border-collapse: collapse;'>
			<thead>
				<tr style='background-color: #f8f9fa;'>
					<th style='width: 30%; text-align: left; padding: 8px;'>File Name</th>
					<th style='text-align: left; padding: 8px;'>Summary</th>
				</tr>
			</thead>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='https://github.com/Lak-MedRida027/Multi-Services-Honeypot-/blob/master/honeypot/mysql_honeypot.py'>mysql_honeypot.py</a></b></td>
					<td style='padding: 8px;'>- MySQL Honeypot ModuleThis module implements a decoy MySQL server designed to attract and monitor malicious connection attempts<br>- It serves as a trap within the overall architecture, enabling the detection and analysis of potential security threats targeting MySQL databases<br>- By mimicking a real MySQL server environment with plausible fake databases and user data, it helps in identifying unauthorized access patterns and malicious activities, contributing to the systems security monitoring and threat intelligence capabilities.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='https://github.com/Lak-MedRida027/Multi-Services-Honeypot-/blob/master/honeypot/rdp_honeypot.py'>rdp_honeypot.py</a></b></td>
					<td style='padding: 8px;'>- Implements an RDP honeypot to simulate a Windows Remote Desktop server, capturing and analyzing connection attempts<br>- It detects potential attack patterns, logs client interactions, and responds with realistic RDP protocol responses to engage and monitor malicious activity<br>- Serves as a deception layer within the security architecture to identify and study RDP-based threats.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='https://github.com/Lak-MedRida027/Multi-Services-Honeypot-/blob/master/honeypot/logger.py'>logger.py</a></b></td>
					<td style='padding: 8px;'>- Establishes a comprehensive logging system for the honeypot project, capturing runtime events and errors<br>- Facilitates real-time monitoring via console output and persistent log storage with timestamped files<br>- Supports effective debugging and audit trails, integrating seamlessly into the overall architecture to enhance observability and maintainability of the honeypot environment.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='https://github.com/Lak-MedRida027/Multi-Services-Honeypot-/blob/master/honeypot/ssh_honeypot.py'>ssh_honeypot.py</a></b></td>
					<td style='padding: 8px;'>- Implements an SSH honeypot that simulates a vulnerable SSH server environment to detect and log unauthorized access attempts<br>- It captures login credentials, mimics a Linux shell, and responds to commands with fake outputs, providing valuable insights into attacker behavior while integrating seamlessly into the overall security architecture.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='https://github.com/Lak-MedRida027/Multi-Services-Honeypot-/blob/master/honeypot/cli.py'>cli.py</a></b></td>
					<td style='padding: 8px;'>- Defines command-line interface for configuring and launching a multi-service honeypot system<br>- Facilitates user input validation, displays system banner and configuration details, and orchestrates the activation of selected honeypot services such as SSH, HTTP, MySQL, and RDP with customizable ports<br>- Serves as the entry point for user interaction and initial setup within the overall architecture.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='https://github.com/Lak-MedRida027/Multi-Services-Honeypot-/blob/master/honeypot/http_honeypot.py'>http_honeypot.py</a></b></td>
					<td style='padding: 8px;'>- Implements a simulated WordPress environment to attract and log malicious activity<br>- It provides fake login, admin, and site pages, mimicking real WordPress behavior<br>- The honeypot captures suspicious requests, including login attempts and common attack vectors, facilitating security monitoring and threat analysis within the overall architecture.</td>
				</tr>
			</table>
		</blockquote>
	</details>
	<!-- config Submodule -->
	<details>
		<summary><b>config</b></summary>
		<blockquote>
			<div class='directory-path' style='padding: 8px 0; color: #666;'>
				<code><b>⦿ config</b></code>
			<table style='width: 100%; border-collapse: collapse;'>
			<thead>
				<tr style='background-color: #f8f9fa;'>
					<th style='width: 30%; text-align: left; padding: 8px;'>File Name</th>
					<th style='text-align: left; padding: 8px;'>Summary</th>
				</tr>
			</thead>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='https://github.com/Lak-MedRida027/Multi-Services-Honeypot-/blob/master/config/settings.py'>settings.py</a></b></td>
					<td style='padding: 8px;'>- Defines core configuration settings for the honeypot system, including logging paths and service parameters across SSH, HTTP, MySQL, and RDP protocols<br>- Facilitates centralized management of environment variables and operational parameters, ensuring consistent deployment and monitoring within the overall architecture of the honeypot infrastructure.</td>
				</tr>
			</table>
		</blockquote>
	</details>
</details>

---

## Getting Started

### Prerequisites

This project requires the following dependencies:

- **Programming Language:** Python
- **Package Manager:** Pip

### Installation

Build Multi-Services-Honeypot- from the source and install dependencies:

1. **Clone the repository:**

    ```sh
    ❯ git clone https://github.com/Lak-MedRida027/Multi-Services-Honeypot-
    ```

2. **Navigate to the project directory:**

    ```sh
    ❯ cd Multi-Services-Honeypot-
    ```

3. **Install the dependencies:**

**Using [pip](https://pypi.org/project/pip/):**

```sh
❯ pip install -r requirements.txt
```

### Usage

Run the project with:

**Using [pip](https://pypi.org/project/pip/):**

```sh
python {entrypoint}
```

### Testing

Multi-services-honeypot- uses the {__test_framework__} test framework. Run the test suite with:

**Using [pip](https://pypi.org/project/pip/):**

```sh
pytest
```

---

## Acknowledgments

- Credit `contributors`, `inspiration`, `references`, etc.

<div align="left"><a href="#top">⬆ Return</a></div>

---
