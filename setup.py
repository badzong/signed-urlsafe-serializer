#!/usr/bin/env python

from distutils.core import setup

setup(name='signed-urlsafe-serializer',
      version='0.1',
      description='Serialize and sign a python dictionary and pack it into a url safe string. Useful for storing data completely on the client side. E.g. user activation without any data in your database.',
      author='Manuel Badzong',
      author_email='manuel@andev.ch',
      url='https://github.com/badzong/signed-urlsafe-serializer.git',
      py_modules=['signedurlsafeserializer',],
      platforms=['any'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Web Environment',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 2',
          'Topic :: Internet :: WWW/HTTP',
          'Topic :: Software Development :: Libraries :: Python Modules',
          ],
     )
