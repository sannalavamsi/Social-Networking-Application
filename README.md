﻿# Social Networking Application

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

# Usage:

## API Endpoints:

### User Registration

- Endpoint: /user/register
- Method: POST
- Description: Register a new user.
- Request Body:

```
{
  "username": "example",
  "email": "example@example.com",
  "password": "*********"
}
```

```
{
  "code": 201,
  "status": "CREATED",
  "message": "User registered successfully."
}
```

### User Login

- Endpoint: /user/login\*
- Method: POST
- Description: Log in a user.
- Request Body:

```
{
  "email": "example@example.com",
  "password": "password123"
}
```

```
{
  "code": 200,
  "status": "OK",
  "message": "User registered successfully."
}
```

### List Users

- Endpoint: /user/users
- Method: GET
- Description: List all users.
- Response:

```
{
  "code": 200,
  "status": "OK",
  "message": "Users fetched successfully.",
  "data": [
    {
      "id": 1,
      "username": "user1",
      "email": "user1@example.com"
    },
    ...
  ],
  "next_page": "URL_TO_NEXT_PAGE",
  "previous_page": "URL_TO_PREVIOUS_PAGE"
}
```

### User Details

- Endpoint: /user/<id>
- Method: GET
- Description: Retrieve details of a specific user by ID.
- Response:

```
{
  "code": 200,
  "status": "OK",
  "message": "User fetched successfully.",
  "data": {
    "id": 1,
    "username": "user1",
    "email": "user1@example.com"
  }
}
```

### Filtering Users

- Endpoint: /user/filtering-users
- Method: GET
- Description: Filtering Users .
  .
- Request Body:

```
{
    "filter_data":"a"
}
```

> or

```
{
    "filter_data":"example@gmail.com"
}
```

- Response:

```
{
    "code": 200,
    "status": "FETCHED",
    "message": "Users fetched successfully.",
    "data": [
        {
            "id": 1,
            "name": "John Doe",
            "email": "john.doe@gmail.com"
        },
        {
            "id": 2,
            "name": "Johnny Appleseed",
            "email": "johnny@example.com"
        }
    ],
    "next_page": "http://localhost:8000/user/filter/?page=2",
    "previous_page": null
}
```

The `FilteringUsers` view allows you to filter users based on their email or name. This view supports pagination and requires authentication.

### List Users to Send Friend Requests

- Endpoint: /users/list-users-to-send-friend-request
- Method: GET
- Description: Retrieve a list of users to whom the current authenticated user can send friend requests. This list excludes users who have already received or sent a friend request to/from the authenticated user.
- Response:

```
{
  "code": 200,
  "status": "SUCCESS",
  "message": "Users fetched successfully.",
  "data": [
    {
      "id": 2,
      "username": "user2",
      "email": "user2@example.com"
    },
    {
      "id": 3,
      "username": "user3",
      "email": "user3@example.com"
    }
  ],
  "next_page": "http://localhost:8000/user/send-friend-request/?page=2",
  "previous_page": null
}
```

### Send Friend Request

- Endpoint: /user/send-friend-request
- Method: POST
- Description: Send a friend request to another user.
- Request Body:

```
{
  "to_user": 2
}
```

```
{
  "code": 201,
  "status": "CREATED",
  "message": "Friend request sent successfully."
}
```

### Accept Friend Request

- Endpoint: /user/accept-friend-request/<from_user_id>
- Method: PUT
- Description: Accept a friend request from another user.
- Response:

```
{
  "code": 200,
  "status": "OK",
  "message": "Friend request accepted successfully."
}
```

### Reject Friend Request

- Endpoint: /user/reject-friend-request/<from_user_id>
- Method: DELETE
- Description: Reject a friend request from another user.
- Response:

```
{
    "code": 200,
    "status": "SUCCESS",
    "message": "Friend request rejected successfully."}
```

### List-accepted-friends

- Endpoint: /user/list-accepted-friends
- Method: GET
- Description: Retrieve a list of users who have accepted friend requests from the authenticated user.

### List Pending Friend Requests

- Endpoint: /user/list-pending-friend-request
- Method: GET
- Description: List all pending friend requests for the authenticated user.
- Response:

```
{
    "code": 200,
    "status": "SUCCESS",
    "message": "Pending friend requests list fetched successfully.",
    "data": [
        {
            "id": 12,
            "from_user": {
                "id": 2,
                "email": "abd@gmail.com",
                "name": "abd"
            },
            "to_user": 2,
            "timestamp": "2024-06-13T11:34:27.790209Z",
            "status": "pending"
        }
    ],
    "next_page": null,
    "previous_page": null
}
```

### List Accepted Friends

- Endpoint: /user/friend-request/accepted
- Method: GET
- Description: List all accepted friends for the authenticated user.
- Response:

```
{
  "code": 200,
  "status": "OK",
  "message": "Accepted friends list fetched successfully.",
  "data": [
    {
      "id": 2,
      "username": "user2",
      "email": "user2@example.com"
    },
    ...
  ],
  "next_page": "URL_TO_NEXT_PAGE",
  "previous_page": "URL_TO_PREVIOUS_PAGE"
}
```

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
