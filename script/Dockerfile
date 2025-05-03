#python version
FROM python:3.9-slim

#sets the working directory
WORKDIR /app

#copies the script files into the container
COPY . /app

#installs the dependencies contained in the requirements .txt file without caching them
RUN pip install --no-cache-dir -r requirements.txt

#runs the script
CMD ["python", "phavicon_phisher.py"]