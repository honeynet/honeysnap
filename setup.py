#!/usr/bin/env python
#
# $Id$
#

import re, os
from distutils.core import setup

setup(name="honeysnap",
      version="1.0rc1",
      description="Honeysnap Data Analysis Framework",
      author="Jed Hale",
      author_email="jed.haile@thelogangroup.biz",
      url="http://www.honeynet.org/tools/danalysis",
	  license="GNU GPL",
      packages=["honeysnap"],
      scripts = ['scripts/honeysnap'],
      )
