from groq import Groq
from webbrowser import open_new_tab
from tempfile import NamedTemporaryFile
from time import sleep

class report(Groq):
    def __init__(self, api_key):
        super().__init__(api_key=api_key)

        with open('reporter/prompt.txt', 'r') as prompt:
            self.system_prompt = prompt.read()


    def generate(self, json_data):
        main = ''
        summary = """
<h1 style="text-align: center;">
  <span style="background-color: #ff0000;"><strong>Executive Summary</strong></span>
</h1>"""
        for i, data in enumerate(json_data.values()):
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
                        "content": 'id =' + str(i+1) + ' ' + str(data)
                    }
                ],
                temperature=0.2,
                max_tokens=8192,
                top_p=1,
                stream=False,
                stop=None,
            )

            print(f"[-] Generated {i+1}/{len(json_data.keys())} alert reports")
            output = str(completion.choices[0].message.content).split('<span>----------</span>')
            main += output[0] + '<br>'
            summary += output[1] + '<br>'
            if i < len(json_data.keys())-1:
                print("Waiting 60 seconds to avoid rate limiting")
                sleep(60)

        # Write report into temporary file into temp directory and open in new tab in browser.
        with NamedTemporaryFile('w', suffix='.html', delete=False) as report:
            report.write(main + summary)
            open_new_tab(report.name)
    

if __name__ == "__main__":
    raise Exception("Attempted to run module file. Run main.py in parent directory.")
    # pass