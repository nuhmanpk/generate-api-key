# API Key Generation Package

This package provides a convenient way to generate API keys using a secret, seed, and an optional include keyword. The generated keys are unique and secure, making them suitable for use in a variety of applications.

The package supports generating API keys using a variety of methods such as UUID v5 and SHA-256 algorithm. The keys are generated using a combination of seed, secret, and include keyword. Additionally, the package allows you to insert the include keyword at a random position in the seed which will make it more difficult to guess.

It is important to keep the secret used to generate the keys secure and not share it with unauthorized parties. Additionally, the package can only be used for legitimate and legal purposes.

Please keep in mind that, even though this package provides a secure way to generate API keys, it is still important to use other security measures such as rate limiting, IP whitelisting, and encryption to protect your API and the data it accesses.

By using this package, you agree to take all necessary precautions to protect the data and resources accessed with the keys from unauthorized access or misuse. It is recommended to consult with a security expert before using this package or handling sensitive data.

# Privacy Policy

This package generates API keys that can be used to access sensitive data or resources. By using this package, you agree to keep the secret used to generate the keys secure and not share it with unauthorized parties. Additionally, the package can only be used for legitimate and legal purposes.

Please be aware that the package may cause a security risk if not used properly. The authors of this package cannot be held responsible for any unauthorized access or misuse of the keys generated by this package.

It is the user's responsibility to ensure the security of the keys and the protection of the data. It is recommended to consult with a security expert before using this package or handling sensitive data.

By using this package, you agree to take all necessary precautions to protect the data and resources accessed with the keys from unauthorized access or misuse.

Please note that this is just an example, and it is important to consult with a legal professional before publishing any package to ensure that it meets all legal and regulatory requirements.


# Installation
To install your package, you can use the pip package manager by running the following command in your command line:

```python
pip install your_package_name
```

# Importing the package
Once the package is installed, you can import the package in your code by using the import statement:
```python
from your_package_name import generateApiKey
```
# Generating an API key
To generate an API key, you can use the generateApiKey() function and pass in the secret, seed, and an optional include keyword. For example:

```python
secret = 'mysecret'
seed = 'randomseed'
api_key = generateApiKey(secret, seed)
print(api_key)
```


```python
secret = 'mysecret'
seed = 'randomseed'
include = "TopSecretWord"
api_key = generateApiKey(secret, seed, include)
print(api_key)
```
This will generate an API key based on the provided secret, seed, and include keyword.

Error handling
It is a good practice to handle errors, you can use the try and except block to handle any exception that may occur during the key generation process.

```python
try:
    secret = 'mysecret'
    seed = 'randomseed'
    include = "Production"
    api_key = generateApiKey(secret, seed, include)
    print(api_key)
except Exception as e:
    print(e)
```

You can use the None return in the package function, to check if the key generation was successful.

```python
api_key = generateApiKey(secret, seed, include)
if api_key is None:
    print("Failed to generate api key")
else:
    print(api_key)
```
