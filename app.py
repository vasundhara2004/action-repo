import hmac
import hashlib
import logging
from flask import Flask, request, jsonify, render_template
from pymongo import MongoClient
from datetime import datetime

app = Flask(__name__)

# Configure logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# GitHub webhook secret - replace with your actual secret or load from environment
GITHUB_SECRET = "your_secret_here"

# MongoDB setup - replace with your connection string if needed
client = MongoClient("mongodb://localhost:27017/")
db = client["webhook_db"]
collection = db["events"]


def verify_signature(request):
    signature = request.headers.get('X-Hub-Signature-256')
    if signature is None:
        return False
    sha_name, signature = signature.split('=')
    if sha_name != 'sha256':
        return False

    mac = hmac.new(GITHUB_SECRET.encode(), msg=request.data, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature)


@app.route('/webhook', methods=['POST'])
def webhook():
    if not verify_signature(request):
        logger.warning("Invalid signature for request")
        return jsonify({'message': 'Invalid signature'}), 403

    event_id = request.headers.get('X-GitHub-Delivery')
    if not event_id:
        logger.warning("Missing GitHub event ID")
        return jsonify({'message': 'Missing event ID'}), 400

    # Check if event already processed
    if collection.find_one({'event_id': event_id}):
        logger.info(f"Duplicate event ignored: {event_id}")
        return jsonify({'message': 'Duplicate event ignored'}), 200

    data = request.json
    event = request.headers.get('X-GitHub-Event')
    logger.info(f"Received GitHub event: {event}, ID: {event_id}")

    author = None
    from_branch = None
    to_branch = None

    if event == 'push':
        author = data.get('pusher', {}).get('name', 'Unknown')
        to_branch = data.get('ref', '').split('/')[-1]
        action_type = 'push'

    elif event == 'pull_request':
        pr = data.get('pull_request', {})
        author = pr.get('user', {}).get('login', 'Unknown')
        from_branch = pr.get('head', {}).get('ref')
        to_branch = pr.get('base', {}).get('ref')
        action_type = 'pull_request'

        # Check if merged pull request (merge action)
        if data.get('action') == 'closed' and pr.get('merged') == True:
            action_type = 'merge'

    else:
        logger.info(f"Ignored unsupported event: {event}")
        return jsonify({'message': 'Unsupported or irrelevant event'}), 400

    timestamp = datetime.utcnow().isoformat() + 'Z'  # ISO 8601 UTC timestamp

    doc = {
        'event_id': event_id,
        'author': author,
        'action': action_type,
        'from_branch': from_branch,
        'to_branch': to_branch,
        'timestamp': timestamp
    }

    collection.insert_one(doc)
    logger.info(f"Stored event: {doc}")
    return jsonify({'message': 'Event stored'}), 200


@app.route('/events')
def get_events():
    events = list(collection.find().sort('_id', -1).limit(10))
    output = []
    for e in events:
        if e['action'] == 'push':
            text = f"{e['author']} pushed to {e['to_branch']}"
        elif e['action'] == 'pull_request':
            text = f"{e['author']} submitted a pull request from {e['from_branch']} to {e['to_branch']}"
        elif e['action'] == 'merge':
            text = f"{e['author']} merged branch {e['from_branch']} to {e['to_branch']}"
        else:
            text = "Unknown action"
        output.append({
            'text': text,
            'timestamp': e['timestamp']
        })
    return jsonify(output)


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
