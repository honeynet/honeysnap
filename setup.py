#!/usr/bin/env python

import re, os
from distutils.core import setup
from distutils.command.build_py import build_py as std_build_py
from distutils.command.clean import clean as std_clean
from distutils.extension import Extension
from Pyrex.Distutils import build_ext as build_ext
from distutils.errors import DistutilsExecError

class build_py(std_build_py):
    """Add foo for building argus constants."""
    define_re = re.compile("#define\s+([^\s]+)\s+([^\s]+)")
    argus_defs=["argus/argus_def.h"]
    def initialize_options(self):
        std_build_py.initialize_options(self)
    def finalize_options(self):
        std_build_py.finalize_options(self)
    def build_argus_defs(self):
        #self.py_modules.append("honeysnap.argus_def")
        f = file("argus/argus_def.h", "r")
        o = file("honeysnap/argus_def.py", "w")
        define_re = self.define_re
        for line in f:
            m = re.search(define_re, line)
            if m:
                name, val = m.groups()
                print >>o, "%s = %s" % (name, val)
        f.close()
        o.close()
    def run(self):
        if self.argus_defs:
            self.build_argus_defs()
        std_build_py.run(self)

class clean(std_clean):
    def run(self):
        std_clean.run(self)
        cleanlist = ['argus/_argus.c']
        for fn in cleanlist:
            print "removing %s." % fn
            os.unlink(fn)

setup(name="honeysnap",
      version="0.1",
      description="Honeysnap Data Analysis Framework",
      author="Jed Hale",
      author_email="jed.haile@thelogangroup.biz",
      url="http://www.honeynet.org/tools/danalysis",
      packages=["honeysnap"],
      scripts = ['scripts/honeysnap'],
      ext_modules=[Extension("honeysnap._argus", ["argus/_argus.pyx"], 
                             include_dirs=["./argus", "./argus/netinet"]),],
      cmdclass={ 'build_py': build_py, 'build_ext': build_ext, 'clean': clean }
      )
