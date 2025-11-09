import os
import yaml
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Load configuration from a YAML file
def load_config():
    if os.path.exists('config.yaml'):
        with open('config.yaml', 'r') as file:
            return yaml.safe_load(file)
    return {}

# Save the configuration to a YAML file
def save_config(config):
    print("Saving config to YAML file...")
    with open('config.yaml', 'w') as file:
        yaml.dump(config, file, default_flow_style=False)
    print("Config saved!")

# Route to handle the main page
@app.route("/", methods=["GET", "POST"])
def index():
    config = load_config()

    if request.method == "POST":
        print("Form submitted.")

        # Handle blocklist actions (add/remove)
        if 'add_blocklist' in request.form:
            url_to_add = request.form.get("new_url")
            if url_to_add:
                if 'blocklist' not in config:
                    config['blocklist'] = []
                config['blocklist'].append(url_to_add)
                save_config(config)
                print(f"Added to blocklist: {url_to_add}")
        
        elif 'remove_blocklist' in request.form:
            url_to_remove = request.form.get("url_to_remove")
            if url_to_remove:
                if 'blocklist' in config and url_to_remove in config['blocklist']:
                    config['blocklist'].remove(url_to_remove)
                    save_config(config)
                    print(f"Removed from blocklist: {url_to_remove}")

        # Handle saving the configuration fields
        if 'save_config' in request.form:
            config['grace_period'] = request.form.get('grace_period', type=int)
            config['random_delay'] = request.form.get('random_delay', type=float)
            config['aggressivness'] = request.form.get('aggressivness', type=int)
            config['sensitivity'] = request.form.get('sensitivity', type=int)
            config['max_throttle'] = request.form.get('max_throttle', type=int)
            config['interval_size'] = request.form.get('interval_size', type=int)
            config['window'] = request.form.get('window', type=int)

            save_config(config)
            print(f"Configuration saved: {config}")

        return redirect(url_for("index"))

    return render_template("index.html", config=config)

if __name__ == "__main__":
    app.run(debug=True)

