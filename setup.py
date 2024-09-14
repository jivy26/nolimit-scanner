from setuptools import setup

setup(
    name='nolimit-scanner',
    version='1.1',
    py_modules=['nolimit'],
    install_requires=[
        'aiofiles==0.8.0',
        'colorama==0.4.4',
        'rich==10.16.2',
        'scapy==2.4.5',
        'tqdm==4.62.3'
    ],
    author='jivy26',
    author_email='jivy26@gmail.com',
    description='Inspired by Masscan, NoLimit is a python based asynchronous port scanner and service enumeration.',
    url='https://github.com/jivy26/nolimit-scanner',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
