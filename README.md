
# MITRE Reporter

A basic tool made for MSU SOC Interns to automatically creates the daily MITRE ATT&CK report for the last 24 hours or any specified duration based on a template used for MSU SOC purposes.

This tool is primarily developed for MSU SOC use and is not expected to work for general use.

## Table of Contents
- [Installation](#installation)
- [Setup](#setup)
- [Usage](#usage)
  - [check](#check)
  - [generate](#generate)
  - [set-env](#set-env)
  - [set-agents](#set-agents)
- [Expected Output](#expected-output)
- [License](#license)

## Installation

1. **Clone the Repository**  
   Clone the repository to your local machine:
   ```bash
   git clone https://github.com/0xLighted/Mitre-Report.git
   cd MITRE-Reporter
   ```

2. **Install Dependencies**  
   Install the project's dependencies using [Poetry](https://python-poetry.org/), this will create a virtual environment and install all necessary packages.

   ```bash
   poetry install
   ```

3. **Activate the Virtual Environment**  
   Once dependencies are installed, activate the virtual environment:
   ```bash
   poetry shell
   ```

   This step is optional if you prefer to run commands directly with `poetry run`.

## Setup

Before using the tool, you must configure environment variables for authentication. Run the following command with your Wazuh login credentials and [Groq API key](https://console.groq.com/keys):
```bash
python reporter set-env <username> <password> <groq_api_key>
```

This command saves your credentials and API key, allowing the tool to collect data.

## Usage

Run the Reporter.ps1 script in powershell to automatically open the poetry shell after the installation process has been completed.
The primary commands are: `check`, `generate`. Below are details and usage examples for each command.

### check

The `check` command displays available alert data with a minimum rule level, allowing users to validate data before generating a report.

**Usage**:
```bash
python reporter check <minimum_level> [duration]
```

- `minimum_level`: The minimum risk level to filter alerts.
- `duration` (optional): Specifies the time range for data, defaulting to the last 24 hours.

**Example**:
```bash
python reporter check 3
python reporter check 3 48
```

_Output_: A table displaying alerts.

<!-- Placeholder for image here -->

### generate

The `generate` command automatically collects data, generates a report based on the provided minimum level and duration, and opens the report in the browser.

**Usage**:
```bash
python reporter generate <minimum_level> [duration]
```

- `minimum_level`: The minimum risk level to include in the report.
- `duration` (optional): Specifies the time range, defaulting to the last 24 hours.

**Example**:
```bash
python reporter generate 3
python reporter generate 3 48
```

**Note**: The report generation process includes a 60-second pause between alerts due to rate-limiting.

<!-- Placeholder for image here -->

### set-env

The `set-env` command configures environment variables for the tool. It should be used before any other command to ensure data access.

**Usage**:
```bash
python reporter set-env <username> <password> <groq_api_key>
```

- `username`: Your Wazuh account username.
- `password`: Your Wazuh account password.
- `groq_api_key`: [API key](https://console.groq.com/keys) required for report generation.

**Example**:
```bash
python reporter set-env myUsername myPassword myAPIKey123
```

### set-agents

The `set-agents` command sets the agents used to filter data in the report. You can specify a list of agent IDs or use `-` to remove the filter.

**Usage**:
```bash
python reporter set-agents <...agent_ids>
```

- `agent_ids`: A list of agent IDs to filter by. Use `-` to clear the filter.

**Example**:
```bash
python reporter set-agents 200 201 202
python reporter set-agents -
```

## Expected Output

- **check**: Outputs a table listing alerts based on the specified minimum risk level and duration.
- **generate**: Generates a single report containing each alert with an executive summary at the end, with a pause between each alert to avoid rate-limiting, and automatically opens a new tab in the browser displaying the full report once completed.

<!-- Placeholder for output images or additional explanations if needed -->

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
