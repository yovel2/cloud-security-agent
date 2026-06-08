# cloud-security-agent

docker build -t cloud-security-agent .

create OUTPUT dir

docker run --rm --network host cloud-security-agent python src/main.py https://github.com/OWASP/NodeGoat
