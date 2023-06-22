# Configuration file for Sphinx documentation builder.

# -- Project information -----------------------------------------------------

project = 'Dropbox Storage Monitor'
author = 'Troy Kelly'

# The full version, including alpha/beta/rc tags
release = 'v1.0'


# -- General configuration ---------------------------------------------------

extensions = ['sphinx.ext.autodoc', 'sphinx.ext.napoleon']

autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
}

# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = False
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = False
napoleon_use_rtype = False

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = None

html_theme = 'alabaster'

# -- Options for HTML output -------------------------------------------------

html_static_path = ['_static']
