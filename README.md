# \# Unified Security Scanner (AppSec \& IaC)

# 

# \## Project Overview

# This project is an automated, Multi-Agent Cloud-Native Application Protection Platform (CNAPP). It integrates Semgrep static analysis with multiple Large Language Models (LLMs) to scan, triage, and automatically patch vulnerabilities across both Application Security (Python logic) and Infrastructure as Code (Docker, Terraform).

# 

# \## Archive Contents (Manifest)

# \* `src/main.py`: The main executable script that orchestrates the workflow and routes tasks.

# \* `src/parser.py`: Logic for parsing Semgrep JSON outputs and extracting vulnerability contexts (including CWE, OWASP data).

# \* `src/triage\_agent.py`: Contains the LLM agent prompts and API interaction logic for False Positive filtering and code remediation.

# \* `Dockerfile`: The container configuration required to run the isolated environment.

# \* `.env.example`: A template file for required environment variables.

# \* `UNIFIED\_SECURITY\_REPORT.md`: A demo artifact showing a generated executive report from a previous scan.

# 

# \## Prerequisites

# 1\. \*\*Docker:\*\* Ensure Docker Desktop or Docker Engine is installed and running.

# 2\. \*\*API Keys:\*\* Rename `.env.example` to `.env` and insert your API keys for Gemini, Groq, and Cohere.

# 3\. \*\*Build the Image:\*\* Before running the tool for the first time, build the Docker image by running this command in the directory containing the `Dockerfile`:

# &#x20;  `docker build -t cloud-security-agent .`

# 

# \## How to Run (Working Executable)

# 

# The project runs interactively inside a Docker container. Use the appropriate command for your operating system:

# 

# \### 1. Windows (Command Prompt - CMD)

# `docker run -it --rm --network host --env-file .env -v "%cd%:/app" -w /app cloud-security-agent python src/main.py`

# 

# \### 2. Linux / macOS (Bash)

# `docker run -it --rm --network host --env-file .env -v "$(pwd):/app" -w /app cloud-security-agent python src/main.py`

# 

# \### 3. Windows (PowerShell)

# `docker run -it --rm --network host --env-file .env -v "${PWD}:/app" -w /app cloud-security-agent python src/main.py`

# 

# \## Usage Example \& Demo

# 1\. Run the execution command for your OS.

# 2\. The terminal will display the tool's banner and ask for a target repository.

# 3\. Paste a vulnerable repository URL to test the system. For example:

# &#x20;  `https://github.com/OWASP/NodeGoat`

# 4\. The system will automatically clone the repo, run the Semgrep scanners, filter false positives using the Triage Agent, route true positives to the respective patching agents, and finally generate a unified Markdown report.

# 5\. The final output artifact (`UNIFIED\_SECURITY\_REPORT.md`) will be saved directly in your current local directory.

