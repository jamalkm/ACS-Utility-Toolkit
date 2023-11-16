#!/usr/bin/env python3

# replicate_acs_users.py
"""
Description: This script replicates users created locally in ACS to Keycloak.
Author: Jamal Kaabi-Mofrad
Python Version: 3.x
Dependencies: requests
License: Apache License 2.0
"""

import csv
import logging
import os
import random
import re
import smtplib
import string
from email.message import EmailMessage
from getpass import getpass

import requests
from requests.auth import HTTPBasicAuth

# Global variables
# Get the directory where the script is located
script_directory = os.path.dirname(os.path.abspath(__file__))
# Name of the CSV file
csv_filename = 'created_users.csv'
# Construct the full path to the CSV file
csv_file_path = os.path.join(script_directory, csv_filename)

# Email body template
html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Email Notification</title>
    <style>
        body {{
            font-family: 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
        }}
    </style>
</head>
<body>
    <p>Dear {name},</p>

    <p>Your account has been successfully migrated to Keycloak.</p>

    <p>Please use the temporary password below to log in to ACS and set a new password:</p>

    <p><strong>Temporary Password:</strong> {password}</p>

    <p>Please note: Upon your first login, you will be prompted to set a new password. This step is mandatory to ensure the security of your 
    account and access to ACS.</p> 


    <p>Best regards,<br>
    Alfresco team</p>
</body>
</html>
"""

# Create a custom logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)  # Set the logging level
# Create handlers
c_handler = logging.StreamHandler()  # Console handler
f_handler = logging.FileHandler('replicate_acs_users.log', mode='a')  # File handler
# Create formatters and add them to the handlers
log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
c_handler.setFormatter(log_format)
f_handler.setFormatter(log_format)
# Add handlers to the logger
logger.addHandler(c_handler)
logger.addHandler(f_handler)


# Utility functions
def get_random_password(length=12):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for _ in range(length))


def get_access_token(base_url, admin_username, admin_password):
    url = f"{base_url}/auth/realms/master/protocol/openid-connect/token"
    form_data = {
        'username': admin_username,
        'password': admin_password,
        'grant_type': 'password',
        'client_id': 'admin-cli',
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    res = requests.post(url, data=form_data, headers=headers)
    res.raise_for_status()  # Will raise an exception for HTTP error
    return res.json()['access_token']


def create_user_in_keycloak(base_url, user_realm, admin_token, user_data):
    url = f"{base_url}/auth/admin/realms/{user_realm}/users"
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json',
    }
    res = requests.post(url, json=user_data, headers=headers)
    if res.status_code == 409:
        logging.warning(f"User '{user_data['username']}' already exists in Keycloak.")
        return False
    elif res.status_code != 201:
        logging.error(f"Error creating user {user_data['username']}: {response.status_code} - {response.text}")
        return False

    return True


def is_valid_email_basic(user_email):
    # A basic regex for email validation, less accurate but doesn't require external packages
    # If more accurate validation required, install 'email-validator' library and use it's 'validate_email' function
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, user_email) is not None


def determine_user_display_name(csv_row):
    if csv_row.get('firstName'):
        return csv_row['firstName']
    elif csv_row.get('lastName'):
        return csv_row['lastName']
    else:
        return csv_row['username']


def send_email(email_server, email_subject, email_body, to, from_email):
    try:
        # Create the email message
        msg = EmailMessage()
        msg.set_content(email_body)
        msg['Subject'] = email_subject
        msg['From'] = from_email
        msg['To'] = to

        # Send the email using the existing server connection
        email_server.send_message(msg)
        return True
    except Exception as exp:
        logging.error(f"An error occurred while sending email: {exp}")
        return False


# Prompt user for input
def get_validate_string_input(prompt):
    while True:
        value = input(prompt).strip()  # .strip() removes leading/trailing whitespace
        if not value:
            print("This field cannot be empty. Please enter a valid value.")
        else:
            return value


def get_validate_password_input(prompt):
    while True:
        value = getpass(prompt)
        if not value:
            print("This field cannot be empty. Please enter a valid value.")
        else:
            return value


def get_validate_integer_input(prompt, default=100):
    while True:
        value = input(f"{prompt} (default is {default}): ").strip()
        if not value:  # If the user just hits Enter, use the default value
            return default
        try:
            number = int(value)
            if number <= 0:
                print("Please enter a positive number.")
            else:
                return number
        except ValueError:
            print("Invalid number. Please enter a valid positive number or just press Enter for default.")


def get_validate_realm_input(prompt, default="alfresco"):
    while True:
        value = input(f"{prompt} (default is {default}): ").strip()
        if not value:  # If the user just hits Enter, use the default value
            return default
        return get_validate_string_input(prompt)


def get_valid_url(url):
    if url.endswith('/'):
        url = url.rstrip('/')  # Remove trailing slashes
        return url
    else:
        return url


def get_yes_no_response(prompt):
    while True:
        res = input(prompt + " (y/n): ").strip().lower()
        if res in ['y', 'yes']:
            return True
        elif res in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' for yes or 'n' for no.")


#  User inputs
repo_base_url = get_valid_url(get_validate_string_input("Enter the ACS base URL (E.g. http://localhost:8080): "))
repo_username = get_validate_string_input("Enter the ACS Admin username: ")
repo_password = get_validate_password_input("Enter the ACS Admin password: ")
max_items = get_validate_integer_input("Enter the number of max items per page when listing people", 100)

keycloak_base_url = get_valid_url(
    get_validate_string_input("Enter the Keycloak base URL (E.g. http://localhost:9090): "))
realm = get_validate_realm_input("Enter the Keycloak 'realm' where your client resides", "alfresco")
keycloak_username = get_validate_string_input("Enter the Keycloak Admin username: ")
keycloak_password = get_validate_password_input("Enter the Keycloak Admin password: ")

is_send_emails = get_yes_no_response("Do you want to send emails to users?")

smtp_config = {}
if is_send_emails:
    smtp_server = get_valid_url(
        get_validate_string_input("Enter the SMTP server: "))
    smtp_port = get_validate_integer_input("Enter the SMTP port", 587)  # For SSL use 465, for TLS/STARTTLS use 587
    smtp_username = get_validate_string_input("Enter the SMTP username: ")
    smtp_password = get_validate_password_input("Enter the SMTP password: ")
    # use_tls is True if the port is 587, False if port is 465, otherwise user input will be used
    use_tls = True if smtp_port == 587 else False if smtp_port == 465 else get_yes_no_response("Do you want the SMTP Server to use TLS?")
    smtp_config['smtp_server'] = smtp_server
    smtp_config['smtp_port'] = smtp_port
    smtp_config['smtp_username'] = smtp_username
    smtp_config['smtp_password'] = smtp_password
    smtp_config['use_tls'] = use_tls

logging.info(
    f"ACS people API: {repo_base_url}/alfresco/api/-default-/public/alfresco/versions/1/people?skipCount=0&maxItems={max_items}&include=capabilities")
logging.info(f"Keycloak users API: {keycloak_base_url}/auth/admin/realms/{realm}/users")

# CSV setup
csv_file = open(csv_file_path, 'w', newline='')
csv_writer = csv.writer(csv_file)
csv_writer.writerow(['username', 'firstName', 'lastName', 'email', 'password'])

# Get Keycloak admin token
access_token = get_access_token(keycloak_base_url, keycloak_username, keycloak_password)

has_more_items = True
skip_count = 0

while has_more_items:
    response = requests.get(
        f"{repo_base_url}/alfresco/api/-default-/public/alfresco/versions/1/people",
        params={'skipCount': skip_count, 'maxItems': max_items, 'include': 'capabilities'},
        auth=HTTPBasicAuth(repo_username, repo_password)
    )
    response.raise_for_status()
    data = response.json()

    for entry in data['list']['entries']:
        user = entry['entry']
        if user['capabilities']['isMutable'] and user['enabled']:
            # Provide default values for potentially missing fields
            user_id = user['id']
            email = user.get('email', '')
            first_name = user.get('firstName', '')
            last_name = user.get('lastName', '')

            random_password = get_random_password()
            create_user_payload = {
                'username': user_id,
                'email': email,
                'firstName': first_name,
                'lastName': last_name,
                'credentials': [{'type': 'password', 'value': random_password, 'temporary': True}],
                'requiredActions': ['UPDATE_PASSWORD'],
                'emailVerified': False,
                'enabled': True,
            }
            if create_user_in_keycloak(keycloak_base_url, realm, access_token, create_user_payload):
                csv_writer.writerow([user_id, first_name, last_name, email, random_password])

    pagination = data['list']['pagination']
    has_more_items = pagination['hasMoreItems']
    skip_count += pagination['count']

csv_file.close()
logging.info("User migration completed. Check the replicate_acs_users.log and created_users.csv files.")

if smtp_config:
    logging.info("Sending emails to users...")

    smtp_server = smtp_config['smtp_server']
    smtp_port = smtp_config['smtp_port']
    smtp_username = smtp_config['smtp_username']
    smtp_password = smtp_config['smtp_password']
    logging.info(f"SMTP pass to {smtp_password}")
    use_tls = smtp_config['use_tls']

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if use_tls:
                server.starttls()
            logging.info("Trying to login to the Gmail server.")
            server.login(smtp_username, smtp_password)
            logging.info("Logged in to Gmail server")

            # Read the CSV file and send emails
            with open(csv_file_path, newline='') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    email = row['email']
                    if email and is_valid_email_basic(email):
                        subject = "Your Account Has Been Migrated from ACS to Keycloak"
                        body = html_template.format(name=determine_user_display_name(row), password=row['password'])
                        if send_email(server, subject, body, email, smtp_username):
                            logging.info(f"Email sent successfully to {email}")
                        else:
                            logging.info(f"Failed to send email to {email}")

    except smtplib.SMTPException as e:
        logging.error(f"An SMTP error occurred: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
