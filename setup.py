from io import open
from os import path

from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='keyvaultlib',
    version='1.0.3',
    description='A KeyVault client wrapper that helps transition between using ADAL (Active Directory Authentication Libraries) and MSI (Managed Service Identity) as a token provider',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/dany74q/keyvaultlib',
    author='Danny Shemesh',
    author_email='dany74q@gmail.com',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='keyvault azure adal msi managed-service-identity',
    packages=find_packages(),
    install_requires=['msrestazure==0.5.0', 'azure-keyvault==1.1.0']
)
