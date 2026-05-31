# cloud-security-agent

bash'
docker build -t cloud-security-agent .
'

bash'
docker run --rm --network host cloud-security-agent python src/main.py https://github.com/octocat/Spoon-Knife'

