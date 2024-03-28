from setuptools import setup

setup(name='ASRepCatcher',
      version='0.2.0',
      description='Make everyone in your VLAN ASREProastable',
      license='GPLv3',
      author='Yassine OUKESSOU',
      author_email='yassine.oukess@gmail.com',
      url='https://github.com/Yaxxine7/ASRepCatcher',
      packages=['ASRepCatcher'],
      install_requires=["scapy", "asn1", "termcolor", "netifaces"],
      entry_points = {
          'console_scripts': ['ASRepCatcher=ASRepCatcher.ASRepCatcher:main']
          }
     )
