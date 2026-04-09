# Lab 01: Building a Secure Python Pipeline

**Difficulty**: Beginner
**Time**: 45-60 minutes
**Prerequisites**: GitHub account, Python 3.10+, git

---

## Lab Objectives

By the end of this lab you will have:

1. Forked a sample vulnerable Python application
2. Created a `.github/workflows/` directory with the secure Python blueprint
3. Intentionally introduced a security vulnerability and watched the pipeline catch it
4. Fixed the vulnerability and confirmed the pipeline passes
5. Observed how Gitleaks prevents credential commits

---

## Setup

### Step 1: Fork the Sample Application

For this lab, create a minimal Python Flask application in a new GitHub repository:

```bash
# Create a new directory for the lab
mkdir lab01-secure-pipeline && cd lab01-secure-pipeline
git init

# Create a minimal Python app
mkdir src tests

# requirements.in (we will generate requirements.txt with hashes)
cat > requirements.in << 'EOF'
flask==3.0.0
requests==2.31.0
EOF

# Generate requirements.txt with hashes
pip install pip-tools
pip-compile --generate-hashes requirements.in

# Create a minimal app
cat > src/app.py << 'EOF'
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "World")
    return jsonify({"message": f"Hello, {name}!"})

if __name__ == "__main__":
    app.run()
EOF

# Create a basic test
cat > tests/test_app.py << 'EOF'
import sys
sys.path.insert(0, "src")
from app import app

def test_hello():
    client = app.test_client()
    response = client.get("/hello?name=Test")
    assert response.status_code == 200
    data = response.get_json()
    assert "Test" in data["message"]

def test_hello_default():
    client = app.test_client()
    response = client.get("/hello")
    assert response.status_code == 200
EOF

# Push to GitHub
git add -A
git commit -m "feat: initial lab01 application"
# Create a GitHub repo and push (use gh CLI or GitHub website)
```

### Step 2: Add the Secure Python Pipeline Blueprint

```bash
mkdir -p .github/workflows
cp [path-to-this-repo]/github-actions/python/full_pipeline.yml .github/workflows/secure-python.yml
```

Adjust the coverage threshold since our app is small:

Open `.github/workflows/secure-python.yml` and change:
```yaml
--cov-fail-under=70
```
to:
```yaml
--cov-fail-under=50
```

```bash
git add .github/
git commit -m "feat: add secure Python pipeline blueprint"
git push
```

Observe the first pipeline run in the Actions tab.

---

## Exercise 1: Introduce a SQLi Vulnerability

Now we will intentionally introduce a vulnerability to see the pipeline catch it.

Add a new insecure endpoint to `src/app.py`:

```python
import sqlite3

@app.route("/user")
def get_user():
    user_id = request.args.get("id", "1")
    # BAD: This is vulnerable to SQL injection
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return jsonify({"result": "ok"})
```

```bash
git add src/app.py
git commit -m "feat: add user endpoint"
git push
```

### Expected Result

The SAST job should fail with a Semgrep finding:
```
python.lang.security.audit.formatted-sql-query
```

This finding indicates SQL injection via string formatting.

**Question**: Which line triggered the finding? What is the attack scenario?

---

## Exercise 2: Fix the Vulnerability

Fix the SQL injection by using a parameterized query:

```python
@app.route("/user")
def get_user():
    user_id = request.args.get("id", "1")
    # GOOD: Parameterized query prevents SQL injection
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return jsonify({"result": "ok"})
```

```bash
git add src/app.py
git commit -m "fix: use parameterized query to prevent SQL injection"
git push
```

**Expected Result**: The SAST job now passes.

---

## Exercise 3: Attempt to Commit a Secret

Try to commit a fake API key and watch Gitleaks block it:

```bash
# Add a fake credential to the code (do NOT use a real key)
echo 'API_KEY = "AKIAIOSFODNN7EXAMPLE123"' >> src/app.py

git add src/app.py
git commit -m "test: add fake key"
git push
```

**Expected Result**: The Gitleaks secret scanning job should fail, detecting the AWS-format key.

**Question**: What would happen if this were a real AWS key? What should you do next?

**Fix**: Remove the hardcoded key and use an environment variable:

```python
import os
API_KEY = os.environ.get("API_KEY", "")  # Never hardcode credentials
```

```bash
git add src/app.py
git commit -m "fix: remove hardcoded credential, use environment variable"
git push
```

---

## Exercise 4: Check the GitHub Security Tab

After the pipeline passes:

1. Go to your repository on GitHub
2. Click the **Security** tab
3. Click **Code scanning alerts**

You should see the Semgrep findings from Exercise 1, even though they are now fixed. GitHub tracks their lifecycle.

- Click on a finding
- Note the "State" field (open vs fixed)
- Click "Dismiss alert" for any false positives and provide a reason

---

## Lab Completion Checklist

- [ ] Pipeline deploys successfully with all security controls
- [ ] SQL injection vulnerability was detected by SAST
- [ ] Vulnerability was remediated and pipeline passed
- [ ] Gitleaks blocked a fake credential commit
- [ ] Reviewed GitHub Security tab findings

---

## Reflection Questions

1. How long did the full security pipeline take to run? How does this compare to not having any security scanning?
2. Which control would have the highest impact on your current projects?
3. What would you need to change to adopt this blueprint in a real production project?
4. What security vulnerabilities are NOT caught by this pipeline? (Think about runtime vulnerabilities, logic flaws, etc.)
