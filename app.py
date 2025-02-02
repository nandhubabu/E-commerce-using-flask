from flask import Flask, render_template
import json
import requests

app = Flask(__name__)

def meme():
    try:
        url = "https://meme-api.com/gimme"
        response = requests.get(url)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        data = response.json()

        # Ensure 'preview' exists and has enough elements
        if "preview" in data and len(data["preview"]) >= 2:
            meme_large = data["preview"][-2]
        else:
            meme_large = data.get("url", None)  # Fallback to direct URL if available

        subreddit = data.get("subreddit", "Unknown")
        return meme_large, subreddit
    except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
        print(f"Error fetching meme: {e}")
        return None, None

@app.route('/', methods=['GET', 'POST'])
def index():
    meme_pic, subreddit = meme()  # Fixed function call
    return render_template('index.html', meme_pic=meme_pic, subreddit=subreddit)

if __name__ == '__main__':
    app.run(debug=True)
