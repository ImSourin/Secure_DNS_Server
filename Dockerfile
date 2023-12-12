FROM ubuntu:latest
LABEL authors="souri"

# Set the working directory inside the container
WORKDIR /app

# Update the package list and install necessary packages
RUN apt-get update && \
    apt-get install -y python3 python3-pip

RUN pip install dnspython aioschedule

# Copy the Python script into the container
COPY dns_server.py .

COPY requirements.txt .

COPY zones/* ./zones/

RUN pip install -r requirements.txt

# Expose the port that the Python server will run on
EXPOSE 31111

EXPOSE 31112

# Command to run the Python server
CMD ["python3", "dns_server.py"]