from setuptools import setup, find_packages

setup(
    name="MITRE-Reporter",
    version="0.1.0",
    description="Automatically creates the daily MITRE ATT&CK report for the last 24 hours or any specified duration based on a template used for MSU SOC purposes.",
    packages=find_packages(exclude=['venv']),
    include_package_data=True,  # Includes non-Python files specified in MANIFEST.in or in package_data
    install_requires=[
        "python-dotenv",
        "groq",
        "pandas",
        "requests"
    ],
    entry_points={
        'console_scripts': [
            'mitre-reporter=reporter.__main__:main',  # Adjust to the main entry point of your app
        ]
    },
)
