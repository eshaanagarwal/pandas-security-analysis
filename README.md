# Task :

### Overview: 

Your task is to secure the Pandas library and its dependencies in a Python environment, ensuring safe operation particularly in restricted or "jailed"
setups. You will identify potential security risks involving unsafe system operations and mitigate them.

**Background**: Pandas is extensively used for data manipulation and analysis. In environments where security is paramount, especially web-based applications, it is crucial to restrict the library's capabilities to prevent unauthorized system access (including data access).

### Challenge Details:
1. **Dependency Analysis**: Identify and list all dependencies of the Pandas
library. Narrow down these dependencies to a subset that could potentially
include unsafe operations related to system access (e.g., sys, os, requests
modules).
2. **Code Analysis**: Analyze the source code of Pandas and its critical
dependencies. Identify all functions and methods in these packages that
could invoke unsafe operations. Map out a call graph for Pandas and the
selected dependencies to see which high-level functions can lead to these
unsafe operations.
3. **Pruning Unsafe Features**: Propose methods to modify or restrict access to
these unsafe functions. Ensure that core functionalities of Pandas and its
dependencies remain intact and usable while enhancing security.
4. **Documentation**: Document your findings, including a list of dependencies
analyzed, identified risky functions, and your proposed solutions. Explain
your approach and the steps taken to secure the library and its
dependencies, providing code snippets and diagrams where applicable.

## Table of Contents
- [Introduction](#introduction)
- [Dependencies Analysis](#dependency-analysis)
- [Code Analysis](#static-code-analysis)
- [Pruning Unsafe Features](#pruning-unsafe-features)


# Solution :

To analyze the dependencies of the Pandas library for potentially unsafe operations related to system access, we can follow these steps:

1. **Extract Dependencies**: Identify the dependencies of the Pandas library.
2. **Analyze Source Code**: Check each dependency for imports of potentially unsafe modules like `sys`, `os`, `requests`, etc.
3. **Summarize Findings**: Document the findings for each dependency.

## Dependency Analysis:
Lets start by first analyzing various depedencies of Pandas for vulnerabilites and security risks. We try to identify potential unsafe operations related to system access. We focus on key dependencies that could pose security risks and provide solutions to mitigate these risks.

#### Identify and List Dependencies
The first step is to identify all dependencies of the Pandas library. This can be achieved by inspecting the setup.py file or using a dependency analysis tool such as `pipdeptree`.

```bash
pip install pipdeptree
pipdeptree -p pandas
```
**Output**:
```bash
pandas==2.0.3
├── numpy [required: >=1.21.0, installed: 1.25.2]
├── python-dateutil [required: >=2.8.2, installed: 2.8.2]
│   └── six [required: >=1.5, installed: 1.16.0]
├── pytz [required: >=2020.1, installed: 2023.4]
└── tzdata [required: >=2022.1, installed: 2024.1]
```
#### Narrowing Down Unsafe Dependencies
Among these dependencies, we will focus on those that potentially include unsafe operations. These include libraries that may use or invoke:

- os module (for file and directory operations)
- sys module (for system-specific parameters and functions)
- requests module (for network operations)
- subprocess module (for spawning new processes)


Python Script : 

```python
import os
import requests
import tarfile
import zipfile
from io import BytesIO
from subprocess import check_output
import re

# Function to get list of dependencies
def get_dependencies(package_name):
    result = check_output([f"pip show {package_name}"], shell=True).decode('utf-8')
    dependencies = []
    for line in result.splitlines():
        if line.startswith("Requires:"):
            dependencies = line.split(":")[1].strip().split(", ")
    return dependencies

# Function to download and extract source code
def download_and_extract(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)
    data = response.json()
    release_info = data['urls'][0]
    download_url = release_info['url']
    response = requests.get(download_url)
    
    if download_url.endswith('.zip'):
        z = zipfile.ZipFile(BytesIO(response.content))
        z.extractall(f"./{package_name}")
    elif download_url.endswith('.tar.gz'):
        t = tarfile.open(fileobj=BytesIO(response.content))
        t.extractall(f"./{package_name}")

# Function to analyze source code for unsafe imports and risky operations
def analyze_source(package_name):
    unsafe_patterns = {
        "sys": r"\bimport\s+sys\b|\bfrom\s+sys\b",
        "os": r"\bimport\s+os\b|\bfrom\s+os\b",
        "requests": r"\bimport\s+requests\b|\bfrom\s+requests\b",
        "subprocess": r"\bimport\s+subprocess\b|\bfrom\s+subprocess\b",
        "open": r"\bopen\s*\(",
        "socket": r"\bimport\s+socket\b|\bfrom\s+socket\b",
    }
    results = {}
    package_dir = f"./{package_name}"
    for root, dirs, files in os.walk(package_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", errors='ignore') as f:
                    content = f.read()
                    for pattern_name, pattern in unsafe_patterns.items():
                        if re.search(pattern, content):
                            if pattern_name not in results:
                                results[pattern_name] = []
                            results[pattern_name].append(file_path)
    return results

# Main function to perform analysis
def main(package_name):
    dependencies = get_dependencies(package_name)
    report = f"# Dependency Analysis for {package_name}\n\n"
    report += "| Dependency | Unsafe Imports and Operations |\n"
    report += "|------------|--------------------------------|\n"

    for dep in dependencies:
        download_and_extract(dep)
        analysis_result = analyze_source(dep)
        unsafe_operations = ", ".join([f"{k}: {v}" for k, v in analysis_result.items()])
        report += f"| {dep} | {unsafe_operations if unsafe_operations else 'None'} |\n"
    
    with open("dependency_analysis.md", "w") as f:
        f.write(report)
    print("Analysis complete. Report saved to dependency_analysis.md")

if __name__ == "__main__":
    main("pandas")
```
On running : 

```bash
python dependency_analysis.py
```

#### Example Output of running `dependency_analysis.md` on Pandas 2.0.3

```bash
Dependency Analysis for pandas
Dependency	Unsafe Imports and Operations
numpy	None
python-dateutil	None
pytz	None
tzdata	None
```

#### Manual Code Review
- Additionally, manually search for potentially unsafe operations:

    - File operations (open, read, write)
    - OS operations (os.system, subprocess)
    - Network operations (requests.get, requests.post)

- Example code to search for specific operations:
```python
grep -r 'os.system' path/to/pandas
grep -r 'subprocess' path/to/pandas
grep -r 'open(' path/to/pandas
```

#### Dependencies of Pandas
The primary dependencies of Pandas include:
1. numpy
2. python-dateutil
3. pytz
4. setuptools
5. six
6. pytables (optional for HDF5 support)
7. numexpr (optional for faster computation)

#### Analyzing Dependencies

1. **setuptools**:

**Description**: A library for packaging Python projects.
**Potential Risk**: Can execute arbitrary code during package installation (`setup.py`).

**Identified Risky Functions**
- `setup()`: This function can execute code defined in `setup.py`.

**Proposed Solutions**
- Review `setup.py` scripts for any arbitrary code execution.
- Use virtual environments to limit the scope of any potential impact.

**Code Snippet to Review setup.py**

```python
# Example setup.py review script
import os

def review_setup_scripts(package_name):
    setup_path = f"./{package_name}/setup.py"
    if os.path.exists(setup_path):
        with open(setup_path, 'r') as file:
            content = file.read()
            print("Reviewing setup.py content:")
            print(content)

# Usage
review_setup_scripts("example_package")
```
2. **pytables**
**Description**: Manages hierarchical datasets using HDF5.
**Potential Risk**: Involves file operations which could be exploited.

**Identified Risky Functions**
- `open_file()`: Opens HDF5 files which can be manipulated to perform unsafe file operations.

**Proposed Solutions**
- Validate file paths and ensure proper file permissions.
- Use secure coding practices when handling file operations.

``` python
import tables

def secure_open_file(file_path):
    if not os.path.isabs(file_path):
        raise ValueError("File path must be absolute.")
    if not os.path.isfile(file_path):
        raise ValueError("File does not exist.")
    
    with tables.open_file(file_path, mode='r') as file:
        print("File opened securely")

# Usage
secure_open_file("/absolute/path/to/file.h5")
```

3. **numexpr**
**Description**: Fast numerical expression evaluator.
**Potential Risk**: Uses JIT compilation which can involve system-level operations.

**Identified Risky Functions**
- `evaluate()`: Compiles and evaluates numerical expressions which can include unsafe operations.

**Proposed Solutions**
- Ensure inputs to `evaluate()` are sanitized and controlled.
- Restrict usage to trusted environments.

**Code Snippet to Sanitize Inputs**
```python
import numexpr as ne

def secure_evaluate(expression, local_dict=None):
    if not isinstance(expression, str):
        raise ValueError("Expression must be a string.")
    if local_dict and not isinstance(local_dict, dict):
        raise ValueError("Local dictionary must be a dict.")
    
    result = ne.evaluate(expression, local_dict=local_dict)
    return result

# Usage
expression = "3 * (a + b)"
local_dict = {'a': 1, 'b': 2}
print(secure_evaluate(expression, local_dict))
```

## Static Code Analysis

#### Static and Execution Call Graph:

In an execution callgraph, the graph is generated through the actual execution of the target program. Therefore, the result is focused on -or limited to- a single set of features involved by this execution. Use execution callgraph when you want to understand or streamline one process in the software.

On the contrary, the static callgraph tries to map all the combinations between the possible processes in a software, using a static analysis (reading the sources without execution). Use static callgraphs to get a global overview of what the code can do and how well connected it is.

We need to identify via static Call Graph to see which high-level functions can lead to these unsafe operations.

For this, we tried to use two libraries called `pyan3==1.1.1` and `code2flow`

**Code to Generate Call Graph:**

- Pyan3

add content here 

```bash
pyan3 pandas/**/*.py --uses --no-defines --colored --grouped --dot > pandas_call_graph.dot
```

- Code2flow

add content her

```bash
code2flow pandas/**/*py --output pandas.png
```
> Despite my best efforts, for the sake of challenge, i dont use `pyan` as it unstable and not under active maintenance and gave me several errors. 
>
> I also tried to experiement with [`code2flow`]() library.
>
> **Known issues with using Code2Flow**
Code2flow is internally powered by ASTs. Most limitations stem from a token not being named what code2flow expects it to be named.
>
> - All functions without definitions are skipped. This most often happens when a file is not included.
Functions with identical names in different namespaces are (loudly) skipped. 
    - E.g. If you have two classes with identically named methods, code2flow cannot distinguish between these and skips them.
>- Imported functions from outside your project directory (including from standard libraries) which share names with your defined functions may not be handled correctly. Instead, when you call the imported function, code2flow will link to your local functions. 
>   - For example, if you have a function search() and call, import searcher; searcher.search(), code2flow may link (incorrectly) to your defined function.
>- Anonymous or generated functions are skipped. This includes lambdas and factories.
If a function is renamed, either explicitly or by being passed around as a parameter, it will be skipped.

**Execution Call Graph:**

To map out a call graph, we can use tools like pycallgraph2 or pycallgraph3 to visualize the call graph of a code and identify which high-level functions can lead to unsafe operations.

Here i use a simple example to demonstrate the the call graph of this function which uses pandas operations. 

```python
from pycallgraph2 import PyCallGraph
from pycallgraph2.output import GraphvizOutput
import pandas as pd

def sample_pandas_operations():
    # Sample Pandas operations
    df = pd.DataFrame({'a': [1, 2, 3], 'b': [4, 5, 6]})
    df['c'] = df['a'] + df['b']
    df['d'] = df['b'] * 2
    result = df.describe()
    return result

if __name__ == "__main__":
    graphviz = GraphvizOutput()
    graphviz.output_file = '/content/pandas_callgraph.png'

    with PyCallGraph(output=graphviz):
        sample_pandas_operations()
```

**PS: Execution Image is present in the submission folder.**


### Using Bandit to flag possible vulnerabilites and sceurity risks.

Bandit is a tool designed to find common security issues in Python code. To do this, Bandit processes each file, builds an AST from it, and runs appropriate plugins against the AST nodes. Once Bandit has finished scanning all the files, it generates a report.

```bash
bandit -r path/to/pandas > issues.txt
bandit -r path/to/numpy > issues.txt
bandit -r path/to/python-dateutil > issues.txt
bandit -r path/to/pytz > issues.txt

```

### Code to process Bandit Generated Issue File:
Here we try to ananlyse various possible issues flagged by bandit library.

We try to do the following things : 
- Store unique issues with their identifiers.
- Count the different severity levels.
- Map severity to different issue types.

Additionally we also try to count the occurences of different CWEs

**Code to check and analyse the issues script** :
```python
import re
from collections import defaultdict

# Initialize dictionaries to store data
issue_count = defaultdict(int)
severity_count = defaultdict(int)
issue_severity_map = defaultdict(list)

# Read the text file
with open('issues.txt', 'r') as file:
    data = file.read()

# Regular expression patterns
issue_pattern = r"Issue: \[(.*?)\]"
severity_pattern = r"Severity: (.*?) "
confidence_pattern = r"Confidence: (.*?) "
location_pattern = r"Location: (.*?) "
cwe_pattern = r"CWE: (.*?) \(.*?\)"
more_info_pattern = r"More Info: (.*?)"

# Find all matches in the data
issues = re.findall(issue_pattern, data)
severities = re.findall(severity_pattern, data)

# Process and count issues
for issue in issues:
    issue_count[issue] += 1

# Process and count severities
for severity in severities:
    severity_count[severity] += 1

# Map severity to issue types
lines = data.splitlines()
current_issue = None
for line in lines:
    issue_match = re.search(issue_pattern, line)
    if issue_match:
        current_issue = issue_match.group(1)
    severity_match = re.search(severity_pattern, line)
    if severity_match and current_issue:
        severity = severity_match.group(1)
        if severity not in issue_severity_map[current_issue]:
            issue_severity_map[current_issue].append(severity)

# Print results
print("Unique Issues and their counts:")
for issue, count in issue_count.items():
    print(f"{issue}: {count}")

print("\nSeverity counts:")
for severity, count in severity_count.items():
    print(f"{severity}: {count}")

print("\nIssue to Severity mapping:")
for issue, severities in issue_severity_map.items():
    print(f"{issue}: {', '.join(severities)}")

# Additional analysis suggestions
def additional_analysis(data):
    # Count occurrences of different CWEs
    cwe_count = defaultdict(int)
    cwes = re.findall(cwe_pattern, data)
    for cwe in cwes:
        cwe_count[cwe] += 1
    print("\nCWE counts:")
    for cwe, count in cwe_count.items():
        print(f"{cwe}: {count}")

# Run additional analysis
additional_analysis(data)
```

**Result :**

```json
Unique Issues and their counts:
B101:assert_used: 13138
B311:blacklist: 1
B301:blacklist: 28
B608:hardcoded_sql_expressions: 13
B404:blacklist: 8
B603:subprocess_without_shell_equals_true: 23
B607:start_process_with_partial_path: 11
B403:blacklist: 12
B110:try_except_pass: 4
B310:blacklist: 1
B701:jinja2_autoescape_false: 3
B405:blacklist: 7
B408:blacklist: 1
B318:blacklist: 1
B410:blacklist: 9
B320:blacklist: 4
B314:blacklist: 2
B307:blacklist: 16
B113:request_without_timeout: 1
B108:hardcoded_tmp_directory: 1

Severity counts:
Low: 13214
Medium: 67
High: 3

Issue to Severity mapping:
B101:assert_used: Low
B311:blacklist: Low
B301:blacklist: Medium
B608:hardcoded_sql_expressions: Medium
B404:blacklist: Low
B603:subprocess_without_shell_equals_true: Low
B607:start_process_with_partial_path: Low
B403:blacklist: Low
B110:try_except_pass: Low
B310:blacklist: Medium
B701:jinja2_autoescape_false: High
B405:blacklist: Low
B408:blacklist: Low
B318:blacklist: Medium
B410:blacklist: Low
B320:blacklist: Medium
B314:blacklist: Medium
B307:blacklist: Medium
B113:request_without_timeout: Medium
B108:hardcoded_tmp_directory: Medium

CWE counts:
CWE-703: 13142
CWE-330: 1
CWE-502: 40
CWE-89: 13
CWE-78: 58
CWE-22: 1
CWE-94: 3
CWE-20: 24
CWE-400: 1
CWE-377: 1
```

- **Severity counts:**
    - Low: 13214
    - Medium: 67
    - High: 3

- **Flagged High Security Risks:**
`B701:jinja2_autoescape_false` was the only dependency that got **high** severity and there were only 3 occurences of this. 

- **Most Common Secrutiy Issue** :
`B101:assert_used` with total of 13138 occurrences


### Security Issues and Fixes

1. **B101:assert_used** (Count: 13138)
   - **Fix:** Replace `assert` statements with proper error handling using exceptions.

2. **B311:blacklist** (Count: 1)
   - **Fix:** Avoid using the `eval` function. Use safer alternatives like `literal_eval` from the `ast` module.

3. **B301:blacklist** (Count: 28)
   - **Fix:** Avoid using insecure functions like `pickle` with untrusted data. Consider using `json` for serialization.

4. **B608:hardcoded_sql_expressions** (Count: 13)
   - **Fix:** Avoid hardcoding SQL queries. Use parameterized queries to prevent SQL injection.

5. **B404:blacklist** (Count: 8)
   - **Fix:** Avoid using `shell=True` in subprocess calls. Use a list of arguments instead.

6. **B603:subprocess_without_shell_equals_true** (Count: 23)
   - **Fix:** Use the `subprocess` module without `shell=True` to prevent shell injection.

7. **B607:start_process_with_partial_path** (Count: 11)
   - **Fix:** Specify the full path when using `subprocess` to start a process.

8. **B403:blacklist** (Count: 12)
   - **Fix:** Avoid using `import *` as it can lead to namespace conflicts. Import only required symbols.

9. **B110:try_except_pass** (Count: 4)
   - **Fix:** Avoid using bare `except` clauses. Catch specific exceptions to handle errors properly.

10. **B310:blacklist** (Count: 1)
    - **Fix:** Avoid using insecure functions like `marshal`. Use safer alternatives like `json`.

11. **B701:jinja2_autoescape_false** (Count: 3)
    - **Fix:** Ensure `autoescape=True` in Jinja2 templates to prevent XSS attacks.

12. **B405:blacklist** (Count: 7)
    - **Fix:** Avoid using the `exec` function. Use safer alternatives like `literal_eval` from the `ast` module.

13. **B408:blacklist** (Count: 1)
    - **Fix:** Avoid using insecure methods. Review and replace them with safer alternatives.

14. **B318:blacklist** (Count: 1)
    - **Fix:** Avoid using `mktemp`. Use `mkstemp` from the `tempfile` module instead.

15. **B410:blacklist** (Count: 9)
    - **Fix:** Avoid using insecure modules. Review and replace them with safer alternatives.

16. **B320:blacklist** (Count: 4)
    - **Fix:** Avoid using insecure functions like `input()` in Python 2. Use `raw_input()` or better alternatives.

17. **B314:blacklist** (Count: 2)
    - **Fix:** Avoid using insecure modules. Review and replace them with safer alternatives.

18. **B307:blacklist** (Count: 16)
    - **Fix:** Avoid using insecure functions. Review and replace them with safer alternatives.

19. **B113:request_without_timeout** (Count: 1)
    - **Fix:** Always specify a timeout when making network requests to avoid hanging indefinitely.

20. **B108:hardcoded_tmp_directory** (Count: 1)
    - **Fix:** Avoid hardcoding `/tmp`. Use the `tempfile` module to create temporary files securely.


### Solutions
- **Prioritization**:
    - Use severity and confidence levels provided by Bandit to prioritize fixing high-severity and high-confidence issues.

- **Automated Testing**:

    - Integrate Bandit and other static analysis tools (like Flake8, MyPy) into your CI/CD pipeline to automate the detection of security issues.
    - Set up automated unit tests to validate the absence of critical vulnerabilities after remediation.

- **Library and Dependency Management**:

    - Regularly update third-party libraries and dependencies to their latest versions to mitigate known vulnerabilities.
    - Use tools like pip-audit to identify and update insecure dependencies.

- **Use Safe Loading Practices**:

    - For deserialization, use safe alternatives like `yaml.SafeLoader` instead of `yaml.Loader` to prevent **remote code execution (RCE) vulnerabilities**.

- **Environment and Configuration**:

    - Always use environment variables for configuration and sensitive information instead of hardcoding them in the source code. Libraries like `python-decouple` can help manage environment variables securely.

## Pruning Unsafe Features :

1. **Modify or Restrict System Call Access in Restricted Environment**:
- Redefine or monkey-patch unsafe functions to raise exceptions when called in restricted environments.
- Example: Override `os.system` and `subprocess.Popen` in restricted setups.
- Restricting OS Access: Patching os.system to prevent system command execution.
- Restricting File Access: Patching open to prevent unauthorized file access.
- Restricting Network Requests: Patching the requests library to prevent network access.

Example Code Snippet :

```python
import os
import builtins
import requests

# Restricting OS access
def restricted_system_call(*args, **kwargs):
    raise PermissionError("System calls are restricted in this environment")

os.system = restricted_system_call

# Restricting file access
def restricted_open(*args, **kwargs):
    raise PermissionError("File access is restricted in this environment")

builtins.open = restricted_open

# Restricting network requests
class RestrictedHTTPAdapter(requests.adapters.HTTPAdapter):
    def send(self, *args, **kwargs):
        raise PermissionError("Network requests are restricted in this environment")

s = requests.Session()
s.mount('http://', RestrictedHTTPAdapter())
s.mount('https://', RestrictedHTTPAdapter())
requests.Session = lambda: s
```

2. **Create a Secure Wrapper**:
- Develop a wrapper around Pandas that controls the use of unsafe operations.

- Create a function to wrap and patch unsafe functions dynamically

```python
import os
import pandas as pd
import numpy as np

UNSAFE_FUNCTIONS = {'system', 'popen', 'exec', 'eval', 'execfile', 'startfile'}

def is_unsafe(func):
    return func.__name__ in UNSAFE_FUNCTIONS

def secure_function(func):
    def wrapper(*args, **kwargs):
        if is_unsafe(func):
            raise ValueError("Unsafe operation not allowed")
        return func(*args, **kwargs)
    return wrapper

def patch_module(module):
    for attr in dir(module):
        if attr.startswith('__') and attr.endswith('__'):
            continue
        try:
            func = getattr(module, attr)
            if callable(func) and is_unsafe(func):
                setattr(module, attr, secure_function(func))
        except Exception as e:
            print(f"Failed to patch {attr} in {module.__name__}: {e}")

for module in [pd, np, os]:
    patch_module(module)
```

or 

**Custom Wrapper**

Create a custom wrapper for Pandas to control access to specific functions:

```python
import pandas as pd
import os
import subprocess

class SecurePandas:
    def __init__(self):
        self.df = pd.DataFrame()

    def read_csv(self, filepath, *args, **kwargs):
        # Restrict access to system directories
        if 'etc' in filepath or 'passwd' in filepath:
            raise ValueError("Access to this file is restricted")
        self.df = pd.read_csv(filepath, *args, **kwargs)
        return self.df
    
    def to_csv(self, filepath, *args, **kwargs):
        # Restrict writing to system directories
        if 'etc' in filepath or 'passwd' in filepath:
            raise ValueError("Writing to this file is restricted")
        self.df.to_csv(filepath, *args, **kwargs)
    
    def eval(self, expr, *args, **kwargs):
        # Prevent execution of potentially unsafe expressions
        if 'os.system' in expr or 'subprocess' in expr:
            raise ValueError("Unsafe expression detected")
        return self.df.eval(expr, *args, **kwargs)

# Example usage
secure_pd = SecurePandas()
df = secure_pd.read_csv('data.csv')
secure_pd.to_csv('output.csv')
df.eval('c = a + b')
```

3. **Check and Replace usage of dangerous functions**:

- Check for usage of dangerous functions like `eval()`, `exec()`, and `pickle` that could lead to code injection attacks. Replace them with safer alternatives like `ast.literal_eval()` for `eval()` and `json` for `pickle`.


- To secure the usage of functions like `eval()`, `exec()`, and `pickle`, which are prone to code injection attacks, and ensure safe loading practices, we can adopt several strategies and best practices:

a. **Avoiding eval()**:

- These functions allow dynamic execution of Python code from a string, which can be exploited if user inputs are not properly sanitized. Instead, use safer alternatives such as ast.literal_eval() for evaluating literals only. This function is much safer as it can only parse literals and not arbitrary code.

- Example:
```python
import ast

user_input = input("Enter a literal value: ")
try:
    parsed_value = ast.literal_eval(user_input)
    print("Parsed value:", parsed_value)
except (ValueError, SyntaxError):
    print("Invalid input.")
```

b. **Replace exec() with Controlled Execution**:

- `exec()` can execute arbitrary Python code, leading to security risks. If you must execute dynamic code, carefully control the environment in which it runs.

Example :
```python
def safe_exec(code, allowed_globals=None, allowed_locals=None):
    if allowed_globals is None:
        allowed_globals = {}
    if allowed_locals is None:
        allowed_locals = {}

    # Override builtins to restrict usage
    allowed_globals['__builtins__'] = {}

    exec(code, allowed_globals, allowed_locals)

# Example usage
code = "x = 2 + 2"
safe_exec(code)
```

c. Replace `pickle` with safer serialization methods like `json`:

```python
import json

data = {'user': 'admin', 'role': 'admin'}
serialized_data = json.dumps(data)
deserialized_data = json.loads(serialized_data)
print(deserialized_data)
```

d. Input Validation and Sanitization:

Always validate and sanitize inputs before processing them to prevent injection attacks.

```python
import re

user_input = input("Enter filename: ")
if re.match("^[a-zA-Z0-9_\-/]+\.txt$", user_input):
    with open(user_input, 'r') as file:
        content = file.read()
else:
    print("Invalid filename.")
```

e. Use Secure Loading Practices:

Use safe loaders for deserialization to prevent remote code execution.

```python
import yaml

def safe_load_yaml(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

data = safe_load_yaml('data.yaml')
print(data)
```

4. **Patch Dangerous Functions**:

- Dynamically patch dangerous functions in your code to prevent their usage.

```python
import pandas as pd
import numpy as np
import builtins
import os
import subprocess

# Define unsafe functions
UNSAFE_FUNCTIONS = {'system', 'popen', 'exec', 'eval', 'execfile', 'startfile', 'open'}

def is_unsafe(func):
    return func.__name__ in UNSAFE_FUNCTIONS

def secure_function(func):
    def wrapper(*args, **kwargs):
        if is_unsafe(func):
            raise ValueError("Unsafe operation not allowed")
        return func(*args, **kwargs)
    return wrapper

def patch_module(module):
    for attr in dir(module):
        if attr.startswith('__') and attr.endswith('__'):
            continue
        try:
            func = getattr(module, attr)
            if callable(func):
                if hasattr(func, '__name__') and is_unsafe(func):
                    setattr(module, attr, secure_function(func))
        except (AttributeError, TypeError):
            continue

# Apply the patch to pandas specifically
patch_module(pd)

# Test the patch in pandas
try:
    pd.eval("1 + 1")  # Should raise ValueError
except ValueError as e:
    print(e)  # Output: Unsafe operation not allowed

# Apply the patch to other modules
for module in [np, os, subprocess, builtins]:
    patch_module(module)

# Test the patch on builtins
try:
    exec("print('Hello World')")  # Should raise ValueError
except ValueError as e:
    print(e)  # Output: Unsafe operation not allowed

# Test the patch on os
try:
    os.system('ls')  # Should raise ValueError
except ValueError as e:
    print(e)  # Output: Unsafe operation not allowed

# Test the patch on subprocess
try:
    subprocess.Popen(['ls'])  # Should raise ValueError
except ValueError as e:
    print(e)  # Output: Unsafe operation not allowed
```

Explanation :
- Patching Mechanism:

    - The patch_module function iterates through attributes of the specified module, checking if they are callable and if they are unsafe.
    - If an attribute is deemed unsafe, it is replaced with a wrapper function that raises a ValueError.
- Handling Special Cases:

    - The patching mechanism avoids non-callable attributes and handles special cases where attributes might not have a __name_



5. **Creating a secure environment (e.g., using virtual environments or containers)**

**Creating a secure environment**:

```python
# Create a virtual environment
python -m venv secure_env

# Activate the virtual environment
source secure_env/bin/activate

# Install Pandas in the secure environment
pip install pandas
```

6. **Using sandboxing techniques**

- For sandboxing, we can use tools like `jailkit` on Linux to restrict system access.

```python
sudo apt-get install jailkit
sudo jk_init -j /path/to/jail basicshell

# Copy the Python interpreter and required libraries to the jail
sudo jk_cp -j /path/to/jail /usr/bin/python3
sudo jk_cp -j /path/to/jail /usr/lib/python3.8

# Add the user to the jail
sudo jk_addjailuser -j /path/to/jail username
```

- Use sandboxing techniques to isolate the execution environment, such as using Docker to run the Python environment in a container.

```python
FROM python:3.9

# Install Pandas
RUN pip install pandas

# Copy application code
COPY . /app
WORKDIR /app

# Run application
CMD ["python", "secure_script.py"]
```

Build and run the Docker container:
```bash
docker build -t pandas-secure .
docker run -it --rm pandas-secure
```

7. **Applying runtime security policies**

Using libraries like `restrictedpython` to restrict code execution.

```python
from RestrictedPython import compile_restricted
from RestrictedPython.Guards import safe_builtins

code = """
import pandas as pd
df = pd.DataFrame({'a': [1, 2, 3], 'b': [4, 5, 6]})
df['c'] = df['a'] + df['b']
"""

compiled_code = compile_restricted(code, filename='<string>', mode='exec')
exec(compiled_code, {'__builtins__': safe_builtins})
```

### Audit python environments using pip audit
`pip audit` is a tool to audit Python environments for packages with known vulnerabilities.

#### Installation
```sh
pip install pip-audit
```

#### Usage
```sh
pip-audit
```

#### Example Output
```
Found 1 vulnerable package!
Name   Version  ID
------ -------- -----
numpy  1.20.1   PYSEC-2021-66
```

#### Mitigating Vulnerabilities with pip audit fix
To mitigate vulnerabilities, you can use `pip-audit` with the `--fix` option to automatically upgrade packages to the secure versions.

#### Usage
```sh
pip-audit --fix
```

#### Example Output
```
Fixed 1 vulnerable package!
Updated numpy from 1.20.1 to 1.20.2
```