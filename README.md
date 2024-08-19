# MailV4l1d8r

MailV4l1d8r is a powerful and efficient email validation tool designed to identify disposable and potentially unsafe email addresses. It utilizes multiple API sources and performs additional checks, such as DNS record verification, WHOIS domain age, SSL certificate validation, and more. This tool is essential for anyone involved in email marketing, cybersecurity, or data management.

## Features

- **Multi-Source Disposable Email Detection**: Checks multiple APIs to detect disposable email addresses.
- **Additional Security Checks**:
  - Validates email format and checks for numeric-heavy local parts.
  - Verifies the presence of DNS records.
  - Checks WHOIS data to determine the domain's age.
  - Validates SSL certificates and examines website content.
- **Customizable and Extensible**: Easily add new validation checks or API sources.
- **User-Friendly Interface**: Includes a visually appealing terminal banner and progress bars.
- **Error Handling**: Gracefully handles errors, such as WHOIS lookup failures, without interrupting the overall validation process.

## Usage

```bash
pip install python-whois

```

To run the tool, simply execute the following command in your terminal:

```bash
python MailV4l1d8r.py
```

You will be prompted to enter an email address, and the tool will perform a series of checks to validate the email.

## Example Output

```bash
Enter the email address: example@example.com

Checking disposable email: 100%|███████████████████████████████████| 5/5 [00:10<00:00,  2.16s/it]

--- Disposable Email Check ---
https://open.kickbox.com/v1/disposable/example@example.com: Not Disposable
https://api.mailcheck.ai/email/example@example.com: Not Disposable
https://isitarealemail.com/api/email/validate?email=example@example.com: Not Disposable
https://checkmail.disify.com/api/email/example@example.com: Not Disposable
https://www.validator.pizza/email/example@example.com: Not Disposable

--- Additional Checks ---
Email Format & Numeric Check: Valid format and non-numeric local part
Forbidden Subdomain Check: No forbidden subdomains
Forbidden Word Check: No forbidden words
DNS Records Check: DNS records found
Domain Age Check: Domain is older than 1 year
SSL Certificate Check: SSL certificate found for https://example.com

--- Final Result ---
Not Disposable
```

## Contributing

Contributions are welcome! If you have any suggestions or improvements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
