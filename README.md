# CharityHeart - Charity Fundraising Platform

A web-based platform for charitable donations with secure authentication and donation management.

## Features

- User registration and authentication
- Secure donation processing
- Cause browsing and management
- Responsive design
- JSON-based data storage

## Setup

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Start the backend server:
   ```bash
   python app.py
   ```

3. Open `src/index.html` in your browser or serve the frontend files using a web server.

## Project Structure

```
├── src/
│   ├── index.html
│   ├── auth/
│   │   ├── login.html
│   │   └── register.html
│   ├── css/
│   │   └── styles.css
│   └── js/
│       ├── auth.js
│       └── config.js
├── app.py
├── requirements.txt
└── data/
    ├── users.json
    └── donations.json
```

## Security

- Passwords are hashed using SHA-256
- JWT-based authentication
- CORS enabled for API access
- Input validation on both frontend and backend

## API Endpoints

- POST /api/register - User registration
- POST /api/login - User authentication
- POST /api/donate - Process donations (requires authentication)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request