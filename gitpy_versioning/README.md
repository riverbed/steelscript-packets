This is a simple Python module to generate PEP-386 compatible
version strings.

If git is available and the project setup.py file is under git control,
git tags are inspected.  The resulting git version is written
to a version file in the root project directory, by default
the file "RELEASE-VERSION"

If git is unavailable or the project setup.py file is *not* under
git control, the version is taken from the RELEASE-VERSION file.
