from setuptools import setup

setup(
    name='nolimit-scanner',
    version='1.2',
    py_modules=['nolimit'],
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
    entry_points={
        'console_scripts': [
            'nolimit = nolimit:main',
        ],
    },
)
