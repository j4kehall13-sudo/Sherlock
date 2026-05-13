import requests
from bs4 import BeautifulSoup
from duckduckgo_search import DDGS
import ollama


LOCAL_MODEL = "gemma3"


SYSTEM_INSTRUCTIONS = """
Your name is Sherlock.

You are Sherlock AI, a local cyberpunk-style research assistant built by the user.
You should refer to yourself as Sherlock when asked your name.

Identity:
1. Your name is Sherlock.
2. You are not ChatGPT inside this application.
3. You are the user's custom local AI assistant interface.
4. You speak clearly, directly, and intelligently.
5. Your tone should feel analytical, precise, and slightly noir/cyberpunk without becoming theatrical or annoying.

Core behaviour:
1. Converse naturally with the user.
2. Help with research, technical explanations, coding, cybersecurity learning, infrastructure planning, and report writing when asked.
3. When web results are provided, use them to support your answer.
4. Cross-reference important claims where possible.
5. Clearly separate confirmed facts from uncertainty.
6. If evidence is weak, say so.
7. Keep answers practical and structured.

Cybersecurity behaviour:
1. Default to defensive guidance.
2. Focus on authorised security work, risk reduction, remediation, compliance, monitoring, logging, backups, patching, and access control.
3. Do not provide harmful exploitation steps.
4. Do not assist with unauthorised access.
5. When discussing tools such as Nmap, Nikto, Gobuster, Burp Suite, Metasploit, or similar, keep guidance scoped to authorised defensive testing.

Research behaviour:
1. If web context is supplied, use it.
2. Do not invent sources.
3. Do not claim you searched the internet unless search results are actually provided.
4. Mention when current information may be incomplete.
5. Provide practical next steps where useful.
"""


class AIClient:
    def __init__(self):
        self.reset()

    def reset(self):
        self.messages = [
            {
                "role": "system",
                "content": SYSTEM_INSTRUCTIONS
            }
        ]

    def get_mode_instructions(self, mode: str) -> str:
        if mode == "General Chat":
            return """
Mode: General Chat.
Respond naturally and clearly.
Keep answers concise unless the user asks for detail.
Do not search the web unless the user asks for current information, research, comparison, or sources.
"""

        if mode == "Research Mode":
            return """
Mode: Research Mode.
Prioritise evidence, source comparison, and uncertainty handling.
Search the web for current, factual, company, product, law, vulnerability, or guidance-related questions.
Separate confirmed facts from assumptions.
Mention source titles or URLs where useful.
End with practical next steps where relevant.
"""

        if mode == "Cybersecurity Mode":
            return """
Mode: Cybersecurity Mode.
Focus on defensive cybersecurity, infrastructure security, risk reduction, compliance, patching, logging, backups, access control, and remediation.
Do not provide harmful exploitation steps or unauthorised access guidance.
When discussing tools, keep advice scoped to authorised defensive testing.
Use clear security terminology and practical checklists.
"""

        return ""

    def search_web(self, query: str, max_results: int = 5) -> list:
        """
        Performs a free DuckDuckGo search.
        Returns a list of search result dictionaries.
        """
        results = []

        try:
            with DDGS() as ddgs:
                for result in ddgs.text(query, max_results=max_results):
                    results.append({
                        "title": result.get("title", ""),
                        "url": result.get("href", ""),
                        "body": result.get("body", "")
                    })

        except Exception as error:
            results.append({
                "title": "Search error",
                "url": "",
                "body": str(error)
            })

        return results

    def fetch_page_text(self, url: str, max_chars: int = 2500) -> str:
        """
        Fetches readable text from a web page.
        This is basic and will not work perfectly on every site.
        """
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 SherlockAI/1.0"
            }

            response = requests.get(
                url,
                headers=headers,
                timeout=10
            )

            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup(["script", "style", "nav", "footer", "header"]):
                tag.decompose()

            text = soup.get_text(separator=" ", strip=True)
            return text[:max_chars]

        except Exception as error:
            return f"Could not fetch page: {error}"

    def build_research_context(self, user_message: str) -> str:
        """
        Searches the web and builds compact research context for the local model.
        """
        search_results = self.search_web(user_message, max_results=5)

        context_parts = []

        for index, result in enumerate(search_results, start=1):
            title = result.get("title", "")
            url = result.get("url", "")
            body = result.get("body", "")

            page_text = ""

            if url:
                page_text = self.fetch_page_text(url, max_chars=1800)

            context_parts.append(
                f"Source {index}\n"
                f"Title: {title}\n"
                f"URL: {url}\n"
                f"Search summary: {body}\n"
                f"Page extract: {page_text}\n"
            )

        return "\n\n".join(context_parts)

    def should_search_web(self, user_message: str) -> bool:
        """
        Basic rule-based check for when Sherlock should search the internet.
        """
        search_triggers = [
            "latest",
            "current",
            "today",
            "recent",
            "news",
            "search",
            "research",
            "find",
            "compare",
            "price",
            "vulnerability",
            "vulnerabilities",
            "cve",
            "company",
            "law",
            "guidance",
            "official",
            "source",
            "sources",
            "cross reference",
            "cross-reference",
            "look up",
            "what happened",
            "has there been"
        ]

        lowered = user_message.lower()

        return any(trigger in lowered for trigger in search_triggers)

    def ask(self, user_message: str, mode: str = "Research Mode") -> str:
        mode_instructions = self.get_mode_instructions(mode)

        should_search = self.should_search_web(user_message) or mode == "Research Mode"

        if should_search:
            research_context = self.build_research_context(user_message)

            final_prompt = f"""
The user is speaking to you inside the Sherlock AI desktop application.

Remember:
- Your name is Sherlock.
- You are Sherlock AI.
- You are not to introduce yourself as ChatGPT.

{mode_instructions}

The user asked:

{user_message}

You searched the web and found this context:

{research_context}

Now answer the user.

Requirements:
1. Answer as Sherlock.
2. Follow the selected mode instructions.
3. Use the web context where relevant.
4. Mention source titles or URLs where useful.
5. Do not pretend you searched sources that are not shown.
6. If the web evidence is weak or incomplete, say so.
7. Give a practical answer.
"""
        else:
            final_prompt = f"""
The user is speaking to you inside the Sherlock AI desktop application.

Remember:
- Your name is Sherlock.
- You are Sherlock AI.
- You are not to introduce yourself as ChatGPT.

{mode_instructions}

User message:
{user_message}
"""

        self.messages.append({
            "role": "user",
            "content": final_prompt
        })

        response = ollama.chat(
            model=LOCAL_MODEL,
            messages=self.messages
        )

        ai_message = response["message"]["content"]

        self.messages.append({
            "role": "assistant",
            "content": ai_message
        })

        return ai_message