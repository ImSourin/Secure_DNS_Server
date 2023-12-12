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

COPY zones/* ./zones/

# Expose the port that the Python server will run on
EXPOSE 53

EXPOSE 31111

# Command to run the Python server
CMD ["python3", "dns_server.py"]