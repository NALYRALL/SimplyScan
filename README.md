# SimplyScan

SimplyScan is a web-based security scanning platform that allows users to scan websites for common security issues through a simple interface.

The project is built with a React frontend, Node.js/Express backend, and a Python-based scanning engine.

## Features

- Website URL scanning
- Web-based scanning interface
- Backend API for handling scan requests
- Python-based security scanning engine
- Scan result display
- Separation between frontend, backend, and scanner components

## Tech Stack

### Frontend
- React.js
- Vite
- JavaScript
- CSS

### Backend
- Node.js
- Express.js
- Axios
- REST API

### Scanner
- Python
- Custom security scanning logic

## Project Structure

```text
SimplyScan/
│
├── client/                 # React frontend
│   ├── public/
│   ├── src/
│   ├── package.json
│   └── vite.config.js
│
├── server/                 # Node.js/Express backend
│   ├── server.js
│   ├── package.json
│   └── package-lock.json
│
├── scanner/                # Python scanning engine
│   ├── scanner.py
│   └── ...
│
├── .gitignore
└── README.md

Security Checks

SimplyScan is designed to perform security-oriented checks against web applications.

Only scan websites that you own or have explicit permission to test.

Do not use SimplyScan to perform unauthorized security testing.

Development

The project is currently under active development.

Planned improvements include:

More security checks
Improved scan result reporting
Better error handling
Scan history
Improved UI/UX
More detailed vulnerability information
Improved scanner accuracy
Authentication and user management
License

This project is currently intended for educational and development purposes.

Author

Himanshu Gupta