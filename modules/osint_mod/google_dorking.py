from serpapi import GoogleSearch
import os
from dotenv import load_dotenv

# Load env vars from .env file
load_dotenv()

class GoogleDorking:
    def __init__(self, platform, username):
        self.platform = platform
        self.username = username
        self.api_key = os.getenv("SERPAPI_API_KEY")  # Now properly loaded
        print("Loaded API Key:", self.api_key)

    def build_query(self):
        if self.platform == "linkedin":
            return f'site:linkedin.com/in "{self.username}"'
        elif self.platform == "instagram":
            return f'site:instagram.com "{self.username}"'
        elif self.platform == "facebook":
            return f'site:facebook.com "{self.username}"'
        else:
            return None

    def run_search(self):
        if not self.api_key:
            return ["❌ SERPAPI_API_KEY is not set. Please configure it in your environment."]

        query = self.build_query()
        if not query:
            return ["❌ Invalid platform or query."]

        try:
            params = {
                "engine": "google",
                "q": query,
                "api_key": self.api_key
            }

            search = GoogleSearch(params)
            results = search.get_dict()
            organic_results = results.get("organic_results", [])

            output = []
            for res in organic_results:
                title = res.get("title")
                link = res.get("link")
                output.append(f"{title} - {link}")

            return output or ["ℹ️ No results found."]
        except Exception as e:
            return [f"❌ Search failed: {str(e)}"]
