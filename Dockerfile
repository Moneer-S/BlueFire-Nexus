# Dockerfile
FROM python:3.11-slim

# Create and set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . /app

# Ensure the bluefire script is executable
RUN chmod +x scripts/bluefire.sh

# Set the default entry point to run the bluefire script
ENTRYPOINT ["./scripts/bluefire.sh"]