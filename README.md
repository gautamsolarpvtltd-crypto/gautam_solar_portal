# Gautam Solar Certificate Portal

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation Steps

1. **Install Required Packages**
```bash
pip install flask flask-sqlalchemy werkzeug
```

2. **Run the Application**
```bash
python enhanced_app.py
```

3. **Access the Portal**
- Homepage: http://127.0.0.1:5000/
- User Portal: http://127.0.0.1:5000/portal
- Admin Panel: http://127.0.0.1:5000/admin

### Default Admin Credentials
- Email: gautamsolarpvtltd@gmail.com
- Password: Skpanchaladmin123

### Admin Routes
- Dashboard: /admin/dashboard
- Users: /admin/users
- Certificates: /admin/certificates
- Company Documents: /admin/company-docs
- Analytics: /admin/analytics
- Branding: /admin/branding

### Features
✅ User Registration & Login
✅ Certificate Download Portal
✅ Admin Dashboard
✅ User Management
✅ Certificate Management
✅ Company Document Management (NEW)
✅ Analytics & Reports
✅ Email Notifications
✅ Download Tracking

### Project Structure
```
gautam-solar-portal/
├── enhanced_app.py          # Main application file
├── database/                # SQLite database folder
├── logs/                    # Application logs
├── templates/              # HTML templates (auto-generated)
├── static/                 # Static files
│   ├── css/
│   ├── js/
│   └── images/
└── README.md
```

### Important Notes
1. Change `app.secret_key` before production
2. Update Gmail credentials for email notifications
3. Use HTTPS in production
4. Regular database backups recommended

### Support
For issues or questions, contact: testing@gautamsolar.com
