from setuptools import setup, find_packages

# Read the contents of your README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read the contents of your requirements.txt file
with open("requirements.txt", "r", encoding="utf-8") as fh:
    install_requires = fh.read().splitlines()

setup(
    name="ReconX",
    version="0.1.0", # Initial version
    author="Your Name/Team Name", # Replace with your name or team name
    author_email="your.email@example.com", # Replace with your email
    description="An advanced, modular, vulnerability reconnaissance and assessment tool.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ReconX", # Replace with your GitHub repo URL
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License", # Assuming MIT License as per your notes
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
    ],
    python_requires='>=3.8', # Specify minimum Python version
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'reconx=reconx:main', # This makes 'reconx' command runnable from terminal
        ],
    },
    include_package_data=True, # Include data files specified in MANIFEST.in or package_data
    # If you have data files that need to be included, uncomment and configure package_data
    # package_data={
    #     'data': ['fingerprints.json', 'local_cve_cache.json'],
    #     'data/wordlists': ['*'], # Include all files in wordlists
    #     'reports/templates': ['base.html'],
    # },
)
