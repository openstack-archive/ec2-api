
from __future__ import print_function

import os
import subprocess
import sys
import warnings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))

sys.path.insert(0, ROOT)
sys.path.insert(0, BASE_DIR)

# This is required for ReadTheDocs.org, but isn't a bad idea anyway.
os.environ['DJANGO_SETTINGS_MODULE'] = 'openstack_dashboard.settings'

# -- General configuration ----------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = ['sphinx.ext.autodoc',
              'sphinx.ext.doctest',
              'sphinx.ext.todo',
              'sphinx.ext.viewcode',
              'openstackdocstheme']

# openstackdocstheme options
repository_name = 'openstack/ec2-api'
bug_project = 'ec2-api'
bug_tag = ''

# autodoc generation is a bit aggressive and a nuisance when doing heavy
# text edit cycles.
# execute "export SPHINX_DEBUG=1" in your terminal to disable

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = 'EC2API Service'
copyright = '2015, OpenStack Foundation'

# If true, '()' will be appended to :func: etc. cross-reference text.
add_function_parentheses = True

# If true, the current module name will be prepended to all description
# unit titles (such as .. function::).
add_module_names = True

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# -- Options for HTML output --------------------------------------------------

# The theme to use for HTML and HTML Help pages.  Major themes that come with
# Sphinx are currently 'default' and 'sphinxdoc'.
# html_theme_path = ["."]
# html_theme = '_theme'
# html_static_path = ['static']
html_theme = 'openstackdocs'

html_last_updated_fmt = '%Y-%m-%d %H:%M'
# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
html_theme_options = {"sidebar_mode": "toc"}

# Output file base name for HTML help builder.
htmlhelp_basename = '%sdoc' % project


git_cmd = ["git", "log", "--pretty=format:'%ad, commit %h'", "--date=local",
    "-n1"]
try:
    html_last_updated_fmt = subprocess.check_output(git_cmd).decode('utf-8')
except Exception:
    warnings.warn('Cannot get last updated time from git repository. '
                  'Not setting "html_last_updated_fmt".')

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title, author, documentclass
# [howto/manual]).
latex_documents = [
        ('index',
         '%s.tex' % project,
         '%s Documentation' % project,
         'OpenStack Foundation', 'manual'),
]
