# CloudTrail-Log-Analyzer-
AWS CloudTrail Analyzer
Description

The AWS CloudTrail Analyzer is a Python script that analyzes AWS CloudTrail logs to identify potential security issues such as unauthorized API calls or changes to security group rules.
Features

    Retrieve the latest CloudTrail log files from AWS
    Analyze CloudTrail logs for potential security issues
    Identify unauthorized API calls or changes to security group rules
    Print information about potential security issues found in CloudTrail logs

Dependencies

    Python 3
    Boto3 library

Installation

    Clone this repository to your local machine.
    Install Python 3 and Boto3 library on your machine.
    Configure AWS credentials on your machine using one of the available methods: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html
    Run the script using the Python interpreter.

Usage

To use the AWS CloudTrail Analyzer script, simply run it using the Python interpreter:

python cloudtrail_analyzer.py

The script will retrieve the latest CloudTrail log files from AWS and analyze them for potential security issues. If any issues are found, it will print information about each event.
Testing

The AWS CloudTrail Analyzer script was tested using the following methods:

    Unit testing: Each function was individually tested to ensure it returns the correct output for various input scenarios.
    Integration testing: The script was tested with real CloudTrail logs to verify its ability to identify potential security issues.

Contributors

    Jane Doe (janedoe@example.com)

License

This project is licensed under the MIT License - see the LICENSE file for details.
