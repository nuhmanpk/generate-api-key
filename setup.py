import pathlib
import setuptools

file = pathlib.Path(__file__).parent

README = (file / "README.md").read_text()

setuptools.setup(
    name="generateApiKey",
    version="0.4.7",
    author="Nuhman Pk",
    author_email="nuhmanpk7@gmail.com",
    long_description = README,
    long_description_content_type = "text/markdown",
    description="This package provides a convenient way to generate API keys using a secret, seed, and an optional include keyword. The generated keys are unique and secure, making them suitable for use in a variety of applications",
    license="MIT",
    url="https://github.com/nuhmanpk/generate-api-key",
    classifiers=[
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'cryptography'
    ],
    packages=setuptools.find_packages(include=['generateApiKey']),
    python_requires=">=3.9",
    project_urls={
        'Documentation': 'https://github.com/nuhmanpk/generate-api-key/blob/main/README.md',
        'Funding': 'https://github.com/sponsors/nuhmanpk',
        'Source': 'https://github.com/nuhmanpk/generate-api-key/',
        'Tracker': 'https://github.com/nuhmanpk/generate-api-key/issues',
    },
    
)
