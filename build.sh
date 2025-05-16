
#pip3 install --upgrade build setuptools
pip3 install build setuptools
if ! python3 -m build
then
    python3 -m build --no-isolation
fi
