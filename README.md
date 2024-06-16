# Social Networking Application

This is a Django REST Framework project for a social networking application where users can connect with friends, send/receive/accept/reject friend requests, and search for other users.

## Features:

### Friend Request Management:

- Send friend requests to other users.
- Accept or reject friend requests.

### User Filtering:

- Filter users by Name or Email Id.

### Technologies Used:

- Backend: Django, Django REST Framework, Python
- Database: MySQL
- Authentication: Basic authentication (using Django REST Framework's Basic authentication)
- Pagination: Custom pagination for listing users
- Logging: Implementation of logging for error handling and debugging

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install foobar.

## Clone the repository

```bash
git clone https://github.com/sannalavamsi/Social-Networking-Application.git
cd SocialNetworkingApplication
```

## Set up virtual environment (optional but recommended)

```bash
python -m venv env
source env/bin/activate  # On Windows use `env\Scripts\activate`
```

## Install dependencies

```bash
pip install -r requirements.txt
```

## Apply the database migrations:

```python
python manage.py migrate
```

## Run the development server:

```python
python manage.py runserver
```
### Usage

Use the provided Postman API collection to test easily.

### Logging

This application uses Python's built-in logging module to log important actions and errors. The logs can be configured in the Django settings file.

### Rate Limiting

To prevent abuse, the API includes rate limiting for sending friend requests. Users can send up to 3 friend requests per minute. If this limit is exceeded, a 429 Too Many Requests response will be returned.

### Error Handling

The API returns appropriate error responses with relevant HTTP status codes and error messages. The following are some common error responses:

- 400 Bad Request: Missing or invalid data in the request.
- 401 Unauthorized: Authentication is required but not provided.
- 403 Forbidden: The authenticated user is not allowed to perform the requested operation.
- 404 Not Found: The requested resource does not exist.
- 500 Internal Server Error: An unexpected error occurred on the server.
