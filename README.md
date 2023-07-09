# PHP-IPAM Scan Agent in Python

This is a small niche tool to perform network scans to update [PHP-IPAM](https://phpipam.net/). It
was developed against the PHP-IPAM API for version 1.5.2, and is completely open to PRs and feature
requests.

## Running the script

There are some pre-requisites for nmap_scan.py which are:

1. You have installed PHP-IPAM, and it is accessible from the network location of the scanner.
2. You have created an API key. I created one API key for all the scanners to use.
    1. As an administrator, go to the Administration drop-down, select "API" and then "+ Create an
    API key".
    2. Give the appliaction a name (I used "scanner"). Make a note of this name. This will be
    part of the configuration you will use later, so keep it memorable, but usable as an
    environment variable!
    3. Make a note of the API key.
    4. App permissions should be set to "Read / Write / Admin".
    5. App security should be set to "SSL with App code token".
    6. Other fields can be configured to your requirements, or left for default.
    7. Click "+ Add" to create the API key.
3. You have created a Scan Agent in PHPIPAM. I create a separate scanner for each network that
will be scanned.
    1. As an administrator, go to the Administration drop-down, select "Scan agents" and then "+
    Create new agent".
    2. Give the scan agent a name - I use "Python NMAP" but you may want to be more specific.
    3. Optionally, add a description for the scan agent. I use this to specify which network
    segment the agent will be scanning.
    4. Make a note of the "Scan agent code".
    5. Leave the Agent Type as-is - this is more for running the PHP-IPAM scanner which requires
    database access.
    6. Click "+ Add" to create the Scan Agent.

### A brief word on the configuration values

There are four mandatory configuration values, which are:

1. `IPAM_SERVER` - the DNS name for the web server where the agent should contact.
2. `IPAM_API_CLIENT` - the API Token Name, defined in step 2.2. of the prerequisites.
3. `IPAM_API_TOKEN` - the API Token, obtained in step 2.3. of the prerequisites.
4. `IPAM_API_AGENT_CODE` - the Scan agent code, obtained in step 3.4 of the prerequisites.

There are also (currently) seven optional configuration values to override default values, which are:

1. `IPAM_SERVER_INSECURE` - should the server reach over HTTPS (set to `0` by default) or HTTP
(set to any other value).
2. `IPAM_SLEEP_DURATION` - how long should the system pause between each cycle to start a new one
(default: `5m` but any `XhXmXs` combination will work here).
3. `IPAM_MIN_TIME_BETWEEN_SCANS` - how long after scanning a particular network segment should the
system wait before scanning it again (default `1h` but any `XhXmXs` combination will work here).
4. `IPAM_ALWAYS_UPDATE` - update the "last seen" value each time the host is checked (default `1`
to perform this action or `0` to only update when the system changes).
5. `IPAM_REMOVE_OLD_HOSTS` - if a host isn't seen for a period of time, should it be actively
deleted from PHP IPAM? (default `1` to remove hosts, `0` to leave them).
6. `IPAM_REMOVE_OLD_HOST_DELAY` - how long after the host has vanished should it be removed when
`IPAM_REMOVE_OLD_HOSTS` is set to 1? (default `48h` but any `XhXmXs` combination will work here).
7. `LOG_LEVEL` - What level of logging is required - default to `INFO` but can also be `DEBUG`.

### Installing on a desktop or server OS

The actual scanner is called "nmap_scan" and requires `nmap` to be installed on your platform of
choice. I have only used Linux, but it will probably work on Mac or BSD based operating systems.

Clone the phpipam-python-scanagent repository into `/opt/phpipam-scanagent` (or choose a more
appropriate path based on your system decisions). Next, create a systemd unit file
in `/etc/systemd/system/phpipam-scanagent.service`, with the following content:

```systemd-unit
[Unit]
Description=NMAP Polling for PHPIPAM
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=3
EnvironmentFile=-/etc/default/phpipam
EnvironmentFile=-/etc/sysconfig/phpipam
EnvironmentFile=-/etc/phpipam
EnvironmentFile=-/opt/phpipam-scanagent/.env
ExecStart=/opt/phpipam-scanagent/nmap_scan/nmap_scan.py

[Install]
WantedBy=multi-user.target
```

Put configuration values (defined above) into the most appropriate file listed in the
"`EnvironmentFile`" paths in the systemd unit file above for your target operating system.

Run `pip3 install -r requirements.txt` in the directory the code has been cloned from to get
the required python modules for the scanner.

Finally, run `systemctl enable --now phpipam-scanagent.service` to start the scanner.

### Running with Docker

Use the following statement:

```bash
docker run -rm ghcr.io/jontheniceguy/publish-packages/phpipam-python-scanagent:latest \
  -n phpipam-scanagent \
  -e IPAM_SERVER=phpipam.example.org \
  -e IPAM_API_CLIENT=MyClient \
  -e IPAM_API_TOKEN=DECAFbad1234567890abcdefghijklmn \
  -e IPAM_API_AGENT_CODE=aabbccddeeffgghhIIJJKKLL12345678
```

This will run the service as a one-off job, but will not give you persistence.

### Running with docker compose or docker-compose

Create your [`docker-compose.yaml`](examples/docker-compose/docker-compose.yaml) file as follows:

```yaml
version: "3.8"

services:
  phpipam-scanner:
    container_name: phpipam-scanner
    image: ghcr.io/jontheniceguy/publish-packages/phpipam-python-scanagent:latest
    restart: on-fail
    environment:
      IPAM_SERVER: phpipam.example.org
      IPAM_API_CLIENT: my_api
      IPAM_API_TOKEN: DECAFbad1234567890abcdefghijklmn
      IPAM_API_AGENT_CODE: aabbccddeeffgghhIIJJKKLL12345678
```

Run `docker compose up -d` or `docker-compose up -d` (depending on which version of
docker compose you have installed).

Instead of specifying the environment variables here, you can also download the
[`.env-example`](nmap_scan/.env-example) adjust to your environment and then change the
`environment:` block in the docker-compose.yaml file to `env_file: ['.env']`.

### Installing in Kubernetes

Create your kubernetes deployment file
([`phpipam-scanner-deployment.yaml`](examples/kubernetes/phpipam-scanner-deployment.yaml)) as
follows (adjusted with your environment variables):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations: {}
  labels:
    role: phpipam-scanner
  name: phpipam-scanner
spec:
  replicas: 1
  selector:
    matchLabels:
      role: phpipam-scanner
  strategy:
    type: Recreate
  template:
    metadata:
      annotations: {}
      labels:
        role: phpipam-scanner
    spec:
      restartPolicy: Always
      containers:
        - image: ghcr.io/jontheniceguy/publish-packages/phpipam-python-scanagent:latest
          name: phpipam-scanner
          resources: {}
          env:
            - name: IPAM_SERVER
              value: phpipam.example.org
            - name: IPAM_API_CLIENT
              value: my_api
            - name: IPAM_API_TOKEN
              value: DECAFbad1234567890abcdefghijklmn
            - name: IPAM_API_AGENT_CODE
              value: aabbccddeeffgghhIIJJKKLL12345678
status: {}
```

Then run `kubectl apply phpipam-scanner-deployment.yaml`
