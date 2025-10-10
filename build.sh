
# We don't want to upgrade build and setuptools every time
#pip3 install --upgrade build setuptools
# Instead we install them only if missing
pip3 install build setuptools tomli || {
    echo "Error installing build and setuptools"
    exit 1
}

python3 -m build || {
    echo "Error building the package"
    exit 1
}

python3 -V >/dev/null 2>&1 && python_cmd=python3 || python_cmd=python


$python_cmd `dirname $0`/pep503-generate.py || {
    echo "Error generating the simple index for pip"
    exit 1
}
