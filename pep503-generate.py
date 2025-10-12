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
    python_version = html.escape(requires_python)

    # Prepare the base URL for downloading the package files from a directory named after the project under dist directory    
    download_url = pyproject['project']['urls'].get('Download')
    if not download_url:
        repository_url = pyproject['project']['urls'].get('Repository')
        if not repository_url:
            raise KeyError("No Download or Repository URL found in pyproject.toml")
        else:
            # Convert the repository URL to a raw URL for GitHub if the domain is github.com
            if "//github.com/" in repository_url:
                # Replace the github.com URL to a raw.githubusercontent.com URL
                download_url = repository_url.replace("//github.com/", "//raw.githubusercontent.com/").rstrip('.git') + f'/refs/heads/main/dist'
            # For gitlab the conversion to raw URL is different
            else:
                download_url = repository_url.rstrip('.git') + f'/-/raw/main/dist'

    # This is the source directory for package files
    src_package_dir = os.path.join(os.path.dirname(__file__), dist_dir)
    # This is the destination directory for package files inside a subdirectory named after the project
    dst_package_dir = os.path.join(os.path.dirname(__file__), dist_dir, project_name)
    # Make the destination directory if it does not exist
    #os.makedirs(dst_package_dir, exist_ok=True)

#    # Iterate on package files in the dist directory and move them to the project subdirectory
#    for filename in os.listdir(src_package_dir):
#        if filename.endswith(('.whl', '.tar.gz')):
#            os.rename(os.path.join(src_package_dir, filename), os.path.join(dst_package_dir, filename))
            
    # Regenerate HTML
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

    # Iterate on package files in the dist directory and generate URL links in the PEP 503 index
    #for filename in os.listdir(dst_package_dir):
    for filename in os.listdir(src_package_dir):
        if filename.endswith(('.whl', '.tar.gz')):
            # Package files will be located in a subdirectory named after the project
            #file_url = f"{download_url}/{project_name}/{filename}"
            file_url = f"{download_url}/{filename}"
            # Generate the HTML link for this file
            html_content += f'<a href="{file_url}" data-requires-python="{python_version}">{filename}</a><br />\n'

    # End HTML    
    html_content += dedent(f'''
            </body>
        </html>
    ''')

    # Write PEP 503 compliant HTML file to dist directory   
    with open(os.path.join(os.path.dirname(__file__), dist_dir, output_file), 'w') as f:
        f.write(html_content)
    # Copy the index.html to the project subdirectory as well
    #with open(os.path.join(os.path.dirname(__file__), dst_package_dir, output_file), 'w') as f:
    #    f.write(html_content)


    # Write the Download command for pip in a separate file
    with open(os.path.join(os.path.dirname(__file__), f'pipinstall_target_{project_name}.dat'), 'w') as f:
        f.write(f"pip install 'git+'{download_url}\n")


if __name__ == "__main__":
    generate_simple_index()