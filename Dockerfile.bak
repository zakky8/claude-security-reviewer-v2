# Use official Python lightweight image
FROM python:3.9-slim

# Install system dependencies (Git is required for repo scanning)
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY claudecode/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the dashboard port
EXPOSE 8000

# Set environment variables for production stability
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Command to run the server
CMD ["python", "server.py"]
