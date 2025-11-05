Blog Website
A simple and extensible blog website built using Python and Flask. The project provides a platform where users can read, create, edit, and manage blog posts through a modern web interface.

Features
Create, edit, and delete blog posts​

User registration and login functionality

Responsive design for desktop and mobile devices

Support for Markdown or rich text in posts

Search and filter through posts

Admin dashboard for managing content

Tech Stack
Component	Stack/Tool
Backend	Python, Flask
Database	SQLite / PostgreSQL
Frontend	HTML, CSS, Bootstrap
ORM	SQLAlchemy
Authentication	Flask-Login
Getting Started
Prerequisites
Python 3.12 (Stick to 3.12 for compatibility)​

pip (Python package manager)

Installation
Clone the Repository

text
git clone https://github.com/yourusername/blog-website.git
cd blog-website
Set Up Virtual Environment

text
python3.12 -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\activate
Install Dependencies

text
pip install -r requirements.txt
Set Up Database

text
flask db init
flask db migrate
flask db upgrade
Run the Application

text
flask run
The site will be available at http://localhost:5000.

Deployment
To deploy on platforms like Render, set the PYTHON_VERSION to 3.12.0 in the environment variables or add a .python-version file in your repo:

text
3.12.0
Usage
Register for a new user account

Log in to create and manage posts

Browse and search posts from other users

Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

License
This project is licensed under the MIT License.
