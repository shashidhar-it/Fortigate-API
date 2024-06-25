# Summary:

This project provides a custom Python wrapper for the Fortigate API, designed to facilitate interaction with Fortinet devices. It includes enhanced logging functionality to 
help track function calls and errors effectively. The CUSTOM_FortinetAPI class, which is central to this project, extends the capabilities of the Fortigate and FortigateAPI 
classes by integrating a logging mechanism and offering methods to retrieve data such as CPU usage,Memory, DNS,Health check, SDWAN zones, FortiGate details , FMG status, FAZ status,
BGP, IPSec, and Fortiswitch Details from Fortinet devices.


# Installation
Clone the repository:

git clone https://github.com/yourusername/fortinet-api-wrapper.git

Navigate to the project directory:
cd fortinet-api-wrapper

# Install required packages:
pip install -r requirements.txt

Usage
Initialize the API Wrapper:
from FortinetAPI import CUSTOM_FortinetAPI

Replace '192.168.1.1' with your Fortinet device IP
api = CUSTOM_FortinetAPI('192.168.1.1')


# Example: 
Retrieve CPU Data:

cpu_data = api.get_cpu_data()

print(cpu_data)

# Contributing
Contributions are welcome! Please follow these steps:

# Fork the repository.
Create a new branch (git checkout -b feature-branch).
Commit your changes (git commit -am 'Add new feature').
Push to the branch (git push origin feature-branch).
Create a new Pull Request.

# Contact
For any inquiries or feedback, please contact shashidhar.it.net@gmail.com
