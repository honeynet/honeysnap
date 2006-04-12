#!/usr/bin/env python

import re, os
from distutils.core import setup

setup(name="honeysnap",
      version="0.2",
      description="Honeysnap Data Analysis Framework",
      author="Jed Hale",
      author_email="jed.haile@thelogangroup.biz",
      url="http://www.honeynet.org/tools/danalysis",
      packages=["honeysnap"],
      scripts = ['scripts/honeysnap'],
      )
