# Network Analysis Dashboard

## Description
This project is a comprehensive real-time network traffic analysis dashboard built with Dash, FastAPI, and PostgreSQL. It captures network traffic, analyzes flows using machine learning models, and provides advanced visualization and alerting capabilities. The system can detect anomalies in network traffic and classify flows as normal or malicious.

## Project Structure
The project is organized into three main components:
- **database**: PostgreSQL database for storing network flows, user data, and analysis results
- **models**: FastAPI application serving a machine learning model for traffic classification
- **frontend**: Dash application providing the user interface for visualization and interaction

## Prerequisites
- Docker
- Docker Compose
- Git

## Environment Configuration
The project uses environment variables for configuration. These are stored in `.env` files:
- `frontend/.env`: Contains frontend-specific configuration
- `database/.env`: Contains database-specific configuration
- `models/.env`: Contains model-specific configuration

## How to Launch the Project

### 1. Clone the repository
```bash
git clone <repository-url>
cd <repository-directory>
```

### 2. Configure environment variables (optional)
The default configuration should work out of the box, but you can modify the `.env` files if needed:
- API_URL: URL for the prediction API (default: http://models:8000)
- OPENAI_API_KEY: API key for OpenAI services (for summary generation)
- DATABASE_URL: Connection string for the PostgreSQL database
- Database credentials (POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD)

### 3. Launch the components in the correct order

#### a. Start the database first
```bash
cd database
docker-compose up -d database
```
Wait for the database to initialize (usually takes a few seconds).

#### b. Start the FastAPI model service
```bash
cd models
docker-compose up -d models
```
The model service will load the pre-trained machine learning model and expose the prediction API on port 8000.

#### c. Start the frontend application
```bash
cd frontend
docker-compose up -d frontend
```
The frontend will connect to both the database and the model service.

A

### 4. Access the dashboard
Open your browser and navigate to:
```
http://localhost:8050
```

Default login credentials:
- Username: admin
- Password: admin123

## Features
- Real-time network flow capture and analysis
- Machine learning-based traffic classification
- Interactive dashboards and visualizations
- Flow reporting and export capabilities
- Multi-user support with secure sessions
- SSH-based remote capture
- Anomaly detection and alerting
- Export capabilities for retraining models

## Stopping the Application
To stop all services:
```bash
docker-compose down
```

To remove volumes (database data) as well:
```bash
docker-compose down -v
```

