from setuptools import setup

setup(name='ASRepCatcher',
      version='0.1.0',
      description='Make everyone in your VLAN ASreproastable',
      license='GPLv3',
      author='Yassine OUKESSOU',
      author_email='yassine.oukess@gmail.com',
      url='https://github.com/Yaxxine7/ASRepCatcher',
      packages=['ASRepCatcher'],
      install_requires=["scapy", "asn1", "termcolor", "netifaces"],
      python_requires='>=3.7.*',
      entry_points = {
          'console_scripts': ['ASRepCatcher=ASRepCatcher.ASRepCatcher:main']
          }
     )