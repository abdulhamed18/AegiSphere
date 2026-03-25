# AegiSphere

AegiSphere is an open-source SIEM and SOC platform designed to transform raw security logs into structured alerts and actionable investigations. It simulates real-world Security Operations Center (SOC) workflows with a focus on ingestion, detection, alert management, and case handling.

---

## Overview

Modern security operations require the ability to process large volumes of log data, detect threats, and respond efficiently. AegiSphere provides a modular platform that models how real SIEM systems operate, including log ingestion pipelines, normalization, detection logic, and investigation workflows.

---

## Key Features

* Log Ingestion System
  Supports structured ingestion of events from multiple sources through API-based pipelines.

* Event Normalization
  Converts raw logs into a consistent schema for analysis and correlation.

* Detection Engine
  Rule-based detection system to identify suspicious or malicious activity.

* Correlation Engine
  Groups related events into higher-level alerts to reduce noise and improve context.

* Alert Management
  Full lifecycle handling including assignment, status transitions, and SLA tracking.

* Case Management
  Create and manage investigation cases linked to alerts.

* Multi-Tenant Architecture
  Supports organization-level isolation of data and users.

* Role-Based Access Control (RBAC)
  Fine-grained permission system for secure access control.

* SOC Workflow Simulation
  Designed to reflect real analyst workflows used in operational environments.

---

## Tech Stack

* Backend: Django
* API: Django REST Framework
* Database: SQLite (development)
* Frontend: HTML, Tailwind CSS, JavaScript

---

## Project Structure

```
AegiSphere/
├── alerts/        # Alert logic, detection, correlation
├── api/           # Ingestion APIs and authentication
├── cases/         # Case management system
├── core/          # Core models, RBAC, workspace logic
├── organizations/ # Multi-tenant organization management
├── workspaces/    # Workspace-level isolation and services
├── parsers/       # Log parsing logic
├── metrics/       # Metrics and dashboards
├── config/        # Django settings and configuration
├── templates/     # Frontend templates
├── static/        # Static assets
```

---

## Getting Started

### 1. Clone the repository

```
git clone https://github.com/abdulhamed18/AegiSphere.git
cd AegiSphere
```

---

### 2. Create virtual environment

```
python -m venv venv
venv\Scripts\activate
```

---

### 3. Install dependencies

```
pip install -r requirements.txt
```

---

### 4. Configure environment variables

Create a `.env` file in the root directory:

```
SECRET_KEY=your-secret-key
```

---

### 5. Run migrations

```
python manage.py migrate
```

---

### 6. Start the server

```
python manage.py runserver
```

---

## Security Notes

* Sensitive values such as `SECRET_KEY` are managed using environment variables.
* The `.env` file is excluded from version control.
* Repository history has been cleaned to remove previously tracked sensitive or unnecessary files.

---

## Roadmap

* Advanced correlation engine (behavior-based / ML enhancements)
* Real-time alerting (WebSocket integration)
* External integrations (Wazuh, ELK, Splunk)
* Enrichment layer (threat intelligence, GeoIP)
* Performance optimization and scaling

---

## Contributing

Contributions are welcome. Please open an issue to discuss changes or submit a pull request with clear descriptions.

---

## License

This project is licensed under the MIT License.
