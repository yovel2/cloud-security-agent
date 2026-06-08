# cloud-security-agent

docker build -t cloud-security-agent .

create OUTPUT dir

docker run --rm --network host \
  -e GEMINI_API_KEY="..." \
  -e GROQ_API_KEY="..." \
  cloud-security-agent python src/main.py https://github.com/OWASP/NodeGoat

# weak explain:
https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a5-security_misconfiguration.html
