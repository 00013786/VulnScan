# EDR (Endpoint Detection and Response) System

A simple EDR system consisting of a client agent written in C++ and a server component built with Django.

## Features

- Process monitoring
- Port scanning
- Suspicious activity detection
- Real-time data collection and visualization
- Web-based dashboard

## Components

### EDR Client (C++)
- Monitors running processes
- Scans open ports
- Detects suspicious activities
- Sends data to server periodically

### EDR Server (Django)
- RESTful API for data collection
- Web dashboard for data visualization
- Process, port, and alert management
- Client management

## Prerequisites

### Client
- C++ compiler (MinGW-w64 recommended)
- CMake
- nlohmann/json library (automatically downloaded via CMake)
- GoogleTest (automatically downloaded via CMake)

### Server
- Python 3.8+
- Django
- Django REST framework

## Building

### Client
```bash
cd edr_client
mkdir build
cd build
cmake -G "MinGW Makefiles" ..
mingw32-make
```

### Server
```bash
cd edr_server
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
```

## Running

### Start the Server
```bash
cd edr_server
python manage.py runserver
```
The server will start at http://localhost:8000

### Start the Client
```bash
cd edr_client/build
./edr_client.exe
```

## Dashboard Access
1. Open your web browser
2. Go to http://localhost:8000/dashboard/
3. Log in with your superuser credentials

## License

MIT License
