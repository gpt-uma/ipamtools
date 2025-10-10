#!/usr/bin/env python3
"""
Generate a simple HTML index for Python packages in the dist directory of this project, following PEP 503.

The purpose is to create a simple package index that can be used by pip for installing packages using the --index-url option and without needing to specify version numbers.

This index will include links to all versions of the package included in the directory so that the pip command can be used to update without any version number.
"""

import os
import html
from textwrap import dedent
import tomli



def generate_simple_index(dist_dir="dist", output_file="index.html"):

    # Read the python project toml file to get package names, respository URLs and versions
    with open(os.path.join(os.path.dirname(__file__), 'pyproject.toml'), 'rb') as f:
        pyproject = tomli.load(f)
    project_name = pyproject['project']['name']
    project_version = pyproject['project']['version']
    requires_python = pyproject['project'].get('requires-python', '>=3.7')
    # Locate download or complete repository URL in project URLs
    
    download_url = pyproject['project']['urls'].get('Download')
    if not download_url:
        repository_url = pyproject['project']['urls'].get('Repository')
        if not repository_url:
            raise KeyError("No Download or Repository URL found in pyproject.toml")
        else:
            download_url = repository_url.rstrip('.git') + '/-/raw/main/dist'

    # Generate HTML
    html_content = dedent(f'''
        <html lang="en">
            <head>
                <meta name="pypi:repository-version" content="1.4">
                <meta name="pypi:project-status" content="active">
                <title>Links for {project_name}</title>
            </head>
            <body>
                <h1>Links for {project_name}</h1>
                    ''')

    # Group files by package name
    for filename in os.listdir(os.path.join(os.path.dirname(__file__), dist_dir)):
        if filename.endswith(('.whl', '.tar.gz')):
            basename = os.path.basename(filename)
            file_url = f"{download_url}/{basename}"
            python_version = html.escape(requires_python)
            html_content += f'<a href="{file_url}" data-requires-python="{python_version}">{filename}</a><br />\n'

    # End HTML    
    html_content += dedent(f'''
            </body>
        </html>
    ''')

    # Write PEP 503 compliant HTML file to dist directory   
    with open(os.path.join(os.path.dirname(__file__), dist_dir, output_file), 'w') as f:
        f.write(html_content)

    # Write the Download command for pip in a separate file
    with open(os.path.join(os.path.dirname(__file__), f'pipinstall_{project_name}.sh'), 'w') as f:
        f.write(f"pip install --index-url {download_url} {project_name}\n")

if __name__ == "__main__":
    generate_simple_index()