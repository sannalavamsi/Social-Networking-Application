# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /code

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /code/
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Copy project files into the working directory
COPY . /code/

# Run migrations and collect static files (if needed)
# RUN python manage.py migrate
# RUN python manage.py collectstatic --noinput

# Specify the command to run your application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "your_project_name.wsgi:application"]
