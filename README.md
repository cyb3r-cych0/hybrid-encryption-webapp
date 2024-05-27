# Hybrid Encryption Web Application

A web application that combines symmetric and asymmetric encryption techniques to secure user data. This project demonstrates the implementation of hybrid encryption in a web environment, ensuring robust security and performance.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Contributing](#contributing)
- [License](#license)
- [Contact Information](#contact-information)

## Installation

To get a local copy up and running, follow these steps.

### Prerequisites

- Python 3.12
- Virtual environment (optional but recommended)

### Backend Setup

1. Clone the repo
   ````
   git clone https://github.com/cyb3r-cych0/hybrid-encryption-webapp.git
   cd hybrid-encryption-webapp

2. Set up the environment
   ````
    - python -m venv venv
    - source venv/bin/activate  
    - venv\Scripts\activate # on windows

3. Install backend dependencies
   ````
    - pip install -r requirements.txt

## Usage

### Running the Backend

1. Navigate to the project root directory and apply migrations
   ````
    - cd hybrid-encryption-webapp
    - python manage.py makemigrations
    - python manage.py migrate

2. Start the backend server
   ````
    - python manage.py runserver
    - Open your browser and go to http://localhost:8000

## Features

    - Hybrid Encryption: Combines AES (symmetric) and RSA (asymmetric) encryption techniques.
    - User Authentication: Secure user login and registration.
    - Data Encryption: Encrypt and decrypt data seamlessly.
    - Responsive Design: User-friendly GUI.
    - Special Feature: All users can encrypt data but ONLY Staff/Superuser decrypts data.

## Contributing

  Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

    Fork the Project
    Create your Feature Branch (git checkout -b feature/AmazingFeature)
    Commit your Changes (git commit -m 'Add some AmazingFeature')
    Push to the Branch (git push origin feature/AmazingFeature)
    Open a Pull Request

## License

  This project is licensed under the Apache 2.0 License - see the [LICENSE](http://www.apache.org/licenses/LICENSE-2.0) file for details.

## Contact Information

    Name: @cyb3r-cych0 | minigates21@gmail.com
    Project Link: https://github.com/cyb3r-cych0/hybrid-encryption-webapp
