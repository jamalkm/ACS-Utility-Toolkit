# User Replication Script: ACS to Keycloak

## Description

This script automates the process of copying users created locally in ACS repository to Keycloak. It retrieves user data from the `people` REST API, processes the data, and creates users in Keycloak using Keycloak's Admin REST API. The script also generates a CSV file containing user information and the generated random password. It also sends emails to users with their credentials if configured.

**Note 1**:\
The random password generated for each user is **temporary**. As a result, users created in Keycloak will be prompted to set a new password on their first login.

**Note 2**:\
The script does not perform user migration; therefore, local users and their credentials will remain in the ACS repository.

## Features

- Fetches users from a specified REST API with pagination support.
- Filters and processes user data based on specific criteria.
- Automatically creates users in Keycloak.
- Generates a CSV file with user details and passwords.
- Optionally sends emails to each user with their login credentials.

## Requirements

- Python 3.x
- `requests` library (for API requests)

## Installation

1. Ensure **Python 3.x** is installed on your system.
2. Clone or download this repository to your local machine.
3. Install required Python library:
    ```bash
    pip install requests
    ```

   **Note**: If you encounter an error such as `command not found: pip`, it's possible that you have both Python 2 and Python 3 installed. In this case, try using pip3:
    ```bash
    pip3 install requests
    ```

## Usage

Run the script from the command line:

```bash
python replicate_acs_users.py
```

Follow the on-screen prompts to enter the necessary information such as ACS and Keycloak URLs, API credentials and SMTP settings for sending emails.

## Output

- Users are created in the specified Keycloak realm.
- A **created_users.csv** file is generated in the script's directory, containing the details of migrated users.
- Emails are sent to users if configured.

## Logging

The script logs its operations in a file named **replicate_acs_users.log** for tracking and debugging purposes.

## License

[Apache License 2.0](/LICENSE)
