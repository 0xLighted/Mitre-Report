from groq import Groq
from webbrowser import open_new_tab
from tempfile import NamedTemporaryFile

class report(Groq):
    def __init__(self, api_key):
        super().__init__(api_key=api_key)

        with open('reporter/prompt.txt', 'r') as prompt:
            self.system_prompt = prompt.read()


    def generate(self, json_data):
        # Send data to Groq API to generate the report.
        completion = self.chat.completions.create(
            model="llama3-70b-8192",
            messages=[
                {
                    "role": "system",
                    "content": self.system_prompt
                },
                {
                    "role": "user",
                    "content": str(json_data)
                }
            ],
            temperature=0.2,
            max_tokens=8192,
            top_p=1,
            stream=False,
            stop=None,
        )

        # Write report into temporary file into temp directory and open in new tab in browser.
        with NamedTemporaryFile('w', suffix='.html', delete=False) as report:
            report.write(str(completion.choices[0].message.content))
            open_new_tab(report.name)



if __name__ == "__main__":
    raise Exception("Attempted to run module file. Run main.py in parent directory.")
    # pass