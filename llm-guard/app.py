from flask import Flask, request, render_template, session
from flask_session import Session 
import prompt
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)  
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        if 'user_prompt' in request.form:  
            user_prompt = request.form['user_prompt']
            
            if not user_prompt:
                return render_template('index.html', original_prompt=None, sanitized_prompt=None, scan_results=None, mappings=None)
            
            enabled_scanners, settings = prompt.init_settings()
            vault = prompt.Vault()
            sanitized_prompt, results = prompt.scan(vault, enabled_scanners, settings, user_prompt)
            mappings = prompt.map_redactions(user_prompt, sanitized_prompt)
            
            # Store mappings in session
            session['mappings'] = mappings
            
            return render_template('index.html', original_prompt=user_prompt, sanitized_prompt=sanitized_prompt, mappings=mappings, scan_results=results)
        
        elif 'redacted_prompt' in request.form: 
            redacted_prompt = request.form['redacted_prompt']
            mappings = session.get('mappings', {})
            
            replaced_prompt = prompt.replace_redactions_with_originals(redacted_prompt, mappings)
            
            return render_template('index.html', replaced_prompt=replaced_prompt)

    return render_template('index.html', original_prompt=None, sanitized_prompt=None, mappings=None, scan_results=None)

if __name__ == '__main__':
    app.run(debug=True)
