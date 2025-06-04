import json
import os
import random
import requests
import string
from dotenv import load_dotenv
from flask import Flask, request, jsonify

load_dotenv()

app = Flask(__name__)

#loads the reference list from the file references.py
app.config.from_object('references.Config')


@app.route('/health', methods=['GET', 'POST'])
def health_check():
    """
    Health check endpoint to verify the service is running.
    Returns:
        json: A JSON object indicating the service status.
    """
    return jsonify({"data": {"status": "ok"}})

@app.errorhandler(404)
def page_not_found(error):
    return jsonify({
        "error": "Not Found",
        "requested_url": request.url
    }), 404

@app.route('/refer/observables', methods=['POST'])
def refer_observables():
    """
    Endpoint to refer observables and retrieve related information.
    Returns:
        json: A JSON object containing information about the observables.
    """
    observables = request.get_json()

    #init output
    relay_output = []

    # Check for entries in custom_pivots
    if app.config['REFERENCES']:
     for item in app.config['REFERENCES']:
      for observable in observables:
       if 'all' in item['obs_types'] or observable['type'] in item['obs_types']:
        id = f"{item['id-string']}-{observable['type']}-{observable['value']}"
        title = item['title']
        description = item['description'].format(obs_value=observable['value'], obs_type=observable['type'])
        url = item['url'].format(obs_value=observable['value'])
        if 'fetcher' in item:
         title, description = item['fetcher'](observable, url)
        relay_output.append({
         'id': id,
         'title': title,
         'description': description,
         'url': url
         })

    return jsonify({'data': relay_output})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)

    return jsonify({'data': relay_output})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
