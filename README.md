# cloud-security-agent

docker build -t cloud-security-agent .

create OUTPUT dir

docker run --rm --network host cloud-security-agent python src/main.py https://github.com/OWASP/NodeGoat

# weak explain:
https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a5-security_misconfiguration.html
