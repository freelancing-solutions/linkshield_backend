# LinkShield Backend API

A comprehensive URL security analysis API built with FastAPI, providing real-time threat detection, AI-powered content analysis, and subscription-based access control.

## Features

- **URL Security Analysis**: Multi-provider threat detection using VirusTotal, Google Safe Browsing, and URLVoid
- **AI-Powered Content Analysis**: Advanced phishing detection and content quality scoring
- **User Authentication**: JWT-based authentication with session management
- **Subscription Management**: Tiered access control with usage quotas
- **Report System**: Community-driven threat intelligence and feedback
- **Advanced Rate Limiting**: Multi-strategy rate limiting with Redis/in-memory backends, user-specific limits, and endpoint-specific restrictions
- **Real-time Monitoring**: Health checks and metrics collection
- **Webhook Support**: Real-time notifications for scan results
- **Social Media Bot Integration**: Twitter, Telegram, and Discord bots for real-time URL analysis and threat detection

## Tech Stack

- **Framework**: FastAPI 0.104.1
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Cache**: Redis for session storage and rate limiting
- **Authentication**: JWT tokens with bcrypt password hashing
- **AI/ML**: OpenAI GPT integration for content analysis
- **Background Tasks**: FastAPI BackgroundTasks for async processing
- **Monitoring**: Prometheus metrics and health checks

## Project Structure

```
linkshield_backend/
├── src/
│   ├── authentication/          # Authentication services
│   ├── auth/                    # Bot authentication and webhook verification
│   ├── bots/                    # Social media bot handlers and gateway
│   ├── config/                  # Configuration management
│   ├── controllers/             # Business logic controllers
│   ├── models/                  # SQLAlchemy database models
│   ├── routes/                  # FastAPI route definitions
│   ├── security/                # Security middleware and utilities
│   └── services/                # External service integrations
├── app.py                       # Main FastAPI application
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variables template
└── README.md                    # This file
```

## Quick Start

### Prerequisites

- Python 3.9+
- PostgreSQL 12+
- Redis 6+
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd linkshield_backend
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Set up database**
   ```bash
   # Create PostgreSQL database
   createdb linkshield_db
   
   # Run migrations
   alembic upgrade head
   ```

6. **Start Redis server**
   ```bash
   redis-server
   ```

7. **Run the application**
   ```bash
   uvicorn app:app --reload --host 0.0.0.0 --port 8000
   ```

### Development Setup

1. **Install development dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up pre-commit hooks**
   ```bash
   pre-commit install
   ```

3. **Run tests**
   ```bash
   pytest
   ```

4. **Code formatting**
   ```bash
   black .
   isort .
   flake8
   ```

## Configuration

### Environment Variables

Key environment variables (see `.env.example` for complete list):

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `SECRET_KEY`: Application secret key
- `JWT_SECRET_KEY`: JWT signing key
- `VIRUSTOTAL_API_KEY`: VirusTotal API key
- `GOOGLE_SAFE_BROWSING_API_KEY`: Google Safe Browsing API key
- `OPENAI_API_KEY`: OpenAI API key

### External API Setup

1. **VirusTotal**: Get API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
2. **Google Safe Browsing**: Enable API in [Google Cloud Console](https://console.cloud.google.com/)
3. **OpenAI**: Get API key from [OpenAI Platform](https://platform.openai.com/)

### Rate Limiting Configuration

The system includes advanced rate limiting with multiple strategies:

- **Sliding Window**: Precise time-based limiting (default)
- **Fixed Window**: Simple counter-based limiting
- **Token Bucket**: Burst-friendly limiting

Rate limits are automatically adjusted based on user subscription tiers:
- **Free**: Basic limits (10 project creations/hour)
- **Basic**: Enhanced limits (15 project creations/hour)
- **Premium**: High limits (50 project creations/hour)

See `docs/api/rate-limiting.md` for detailed configuration options.

## API Documentation

Once the server is running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

## API Endpoints

### Authentication
- `POST /api/v1/user/register` - User registration
- `POST /api/v1/user/login` - User login
- `POST /api/v1/user/logout` - User logout
- `POST /api/v1/user/refresh` - Refresh JWT token

### URL Analysis
- `POST /api/v1/url-check` - Analyze single URL
- `POST /api/v1/url-check/bulk` - Analyze multiple URLs
- `GET /api/v1/url-check/{check_id}` - Get analysis results
- `GET /api/v1/url-check/{check_id}/history` - Get URL history

### User Management
- `GET /api/v1/user/profile` - Get user profile
- `PUT /api/v1/user/profile` - Update user profile
- `POST /api/v1/user/change-password` - Change password
- `GET /api/v1/user/api-keys` - Manage API keys

### Reports
- `POST /api/v1/reports` - Submit threat report
- `GET /api/v1/reports` - List user reports
- `PUT /api/v1/reports/{report_id}/vote` - Vote on report

### Health & Monitoring
- `GET /api/v1/health` - Basic health check
- `GET /api/v1/health/detailed` - Detailed health status
- `GET /api/v1/metrics` - Prometheus metrics

## Usage Examples

### Analyze a URL

```bash
curl -X POST "http://localhost:8000/api/v1/url-check" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "scan_type": "full",
    "include_ai_analysis": true
  }'
```

### Register a new user

```bash
curl -X POST "http://localhost:8000/api/v1/user/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "full_name": "John Doe"
  }'
```

## Deployment

### Docker Deployment

1. **Build Docker image**
   ```bash
   docker build -t linkshield-api .
   ```

2. **Run with Docker Compose**
   ```bash
   docker-compose up -d
   ```

### Production Deployment

1. **Use production WSGI server**
   ```bash
   gunicorn app:app -w 4 -k uvicorn.workers.UvicornWorker
   ```

2. **Set up reverse proxy** (Nginx example)
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

## Monitoring

- **Health Checks**: `/api/v1/health` and `/api/v1/health/detailed`
- **Metrics**: Prometheus metrics at `/api/v1/metrics`
- **Logging**: Structured JSON logs with configurable levels
- **Database Monitoring**: Connection pool and query performance

## Security

- JWT-based authentication with refresh tokens
- Advanced rate limiting with multiple strategies (sliding window, fixed window, token bucket)
- User-specific and subscription-based rate limits
- Redis and in-memory storage backends for rate limiting
- Input validation and sanitization
- SQL injection prevention with SQLAlchemy ORM
- CORS configuration for cross-origin requests
- Security headers middleware
- Password hashing with bcrypt

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Check the API documentation at `/docs`
- Review the health check endpoints for system status