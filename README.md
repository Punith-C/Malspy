
# Malspy

Malspy is a malware analysis toolkit primarily developed in Python with performance-critical components in Cython, C, and C++. It provides basic utilities and backend services to assist security researchers and analysts in investigating and understanding malicious software.

## Features

- Static and dynamic malware analysis capabilities.
- Integration-ready backend built using FastAPI.
- Lightweight and extensible architecture for custom expansions.
- Written mainly in Python, with some modules in C/C++ for speed.
- Provides an API server for interacting with malware analysis workflows.

## Installation and Setup

1. Clone the repository:
   ```
   git clone https://github.com/Punith-C/Malspy.git
   cd Malspy/Backend
   ```

2. Create a Python virtual environment:
   ```
   python3 -m venv venv
   ```

3. Activate the virtual environment:
   ```
   source venv/bin/activate
   ```

4. Install required Python dependencies:
   ```
   pip install -r requirements.txt
   ```

5. Start the backend server with auto-reload:
   ```
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

6. Access the API documentation and testing UI at:
   ```
   http://localhost:8000/docs
   ```

## Usage

Use the provided RESTful API endpoints to upload malware samples, retrieve analysis reports, or integrate Malspy’s capabilities into other security tools via HTTP requests.

## Development

- Modular code structure makes it easy to extend analysis techniques.
- FastAPI framework offers automatic interactive API docs.
- Use the `--reload` flag in Uvicorn to auto-refresh backend on source changes.

## Contributing

Contributions are welcome! Fork the repository, make your changes, and open a pull request. For major modifications, please open an issue first to discuss your plans.

## License

No license is specified for this project currently. Please get in touch with the repository owner for permissions and terms of use.
