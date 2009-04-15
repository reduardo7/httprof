#!/usr/bin/env python

"""The world's worst HTML, CSS, and JavaScript minifier. It's so bad, it is
only suitable as a heuristic to check if a given blob of text is likely to
have been minified. Incidentally, that's all I use it for. Coincidence? You
decide.

Usage:

      minify.py somefile > minified
"""

import re

THRESHOLD = 0.9

splitter = re.compile("\s+").split
html_comment = re.compile("(<!--.*?-->)", re.MULTILINE)
c_comment = re.compile("(/\*.*?\*/)", re.MULTILINE)
cpp_comment = re.compile("(//.*)$", re.MULTILINE)


def remove_comments(text):

      """text: Some text, as a string. Returns: A copy of text with all
HTML, C-style and C++-style comments removed."""

      text = html_comment.sub("", text)
      text = c_comment.sub("", text)
      return cpp_comment.sub("", text)


def minify(text):
 
      """text: Some text, as a string. Returns: A copy of text with all
instances of one or more spaces replaced with \n."""

      return "\n".join(splitter(remove_comments(text)))


def is_text_minimal(text, minified_text):

      """text: The original text. minified_text: The candidate minimal text,
such as from minify(text). Returns True if minified_text is not
"significantly" (see THRESHOLD) smaller than text; False otherwise."""

      r = float(len(m)) / len(t)
      return r > THRESHOLD


if __name__ == "__main__":
      import sys

      if 2 != len(sys.argv):
            print __doc__
            sys.exit(1)

      t = file(sys.argv[1], "rb").read()
      m = minify(t)
      print m
      r = float(len(m)) / len(t)
      sys.stderr.write("Minification ratio: %.3f (minimal: %s)\n" % (r, str(is_text_minimal(t, m))))

