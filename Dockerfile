# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Install dependencies if requirements.txt exists
RUN pip install --no-cache-dir -r requirements.txt || true

# Run the bot
CMD ["python", "bot.py"]
