import subprocess

# Define the filename
file_name = "list-monkeytype.txt"

# Check if the file exists
try:
    with open(file_name, "r") as file:
        file_contents = file.read()
except FileNotFoundError:
    print(f"File not found: {file_name}")
    exit(1)

# Find all occurrences of "module_name" in the file
module_names = file_contents.split("\n")

# Execute the commands with "monkeytype apply" and the "module_name"
for module_name in module_names:
    if "test" not in module_name and "model" not in module_name and "" != module_name:
        command = f"monkeytype apply {module_name}"
        print(f"Executing: {command}")
        subprocess.run(command, shell=True)
    else:
        print(f"Bypass: {module_name}")
