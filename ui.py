import os
import yaml
import subprocess
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Global variable to track the running process
script_process = None

# Load configuration from a YAML file
def load_config():
    if os.path.exists('config.yaml'):
        with open('config.yaml', 'r') as file:
            return yaml.safe_load(file)
    return {}

# Save the configuration to a YAML file
def save_config(config):
    with open('config.yaml', 'w') as file:
        yaml.dump(config, file, default_flow_style=False)

# Route to handle the main page
@app.route("/", methods=["GET", "POST"])
def index():
    global script_process
    config = load_config()

    if request.method == "POST":
        if 'add_blocklist' in request.form:
            url_to_add = request.form.get("new_url")
            if url_to_add:
                if 'blocklist' not in config:
                    config['blocklist'] = []
                config['blocklist'].append(url_to_add)
                save_config(config)
        
        elif 'remove_blocklist' in request.form:
            url_to_remove = request.form.get("url_to_remove")
            if url_to_remove:
                if 'blocklist' in config and url_to_remove in config['blocklist']:
                    config['blocklist'].remove(url_to_remove)
                    save_config(config)

        elif 'save_config' in request.form:
            # Update the configuration fields
            config['grace_period'] = request.form.get('grace_period', type=int)
            config['random_delay'] = request.form.get('random_delay', type=float)
            config['aggressivness'] = request.form.get('aggressivness', type=float)
            config['sensitivity'] = request.form.get('sensitivity', type=int)
            config['max_throttle'] = request.form.get('max_throttle', type=float)
            config['interval_size'] = request.form.get('interval_size', type=int)
            config['window'] = request.form.get('window', type=int)
            save_config(config)

        elif 'run_script' in request.form:
            # Run the external Python script
            if script_process is None or script_process.poll() is not None:
                try:
                    print("Running script...")
                    # Using subprocess.run for blocking execution
                    # Ensure you have the correct path to the script
                    script_process = subprocess.Popen(
                        ['python3', 'proxy.py'],  # Replace 'your_script.py' with your actual script
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )

                    # Optionally, if you want to capture the output and error
                    #stdout, stderr = process.communicate()  # This waits for the process to complete
                    #if stdout:
                    #    print("Script output:", stdout)
                    #if stderr:
                    #    print("Script error:", stderr)
                except Exception as e:
                    print(f"Error running script: {e}")

        elif 'stop_script' in request.form:
            # Stop the running script if it exists
            if script_process is not None:
                script_process.terminate()
                script_process = None

        return redirect(url_for("index"))

    return render_template("index.html", config=config, script_process=script_process)

if __name__ == "__main__":
    app.run(debug=True)

