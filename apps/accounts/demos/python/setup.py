from setuptools import setup, find_packages


setup(
    name='xpam-pam',
    version='0.0.1',
    packages=find_packages(),
    install_requires=[
        'requests',
        'httpsig'
    ],
    description='XPAM PAM client',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
        author='XPAM',
    classifiers=[
        'Programming Language :: Python :: 3',
    ],
    python_requires='>=3.6',
)
