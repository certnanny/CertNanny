# Checklist for tagging releases

* Update "README.md" with information about the new release
* Move the "latest stable release" tag in "README.md" if appropriate
* Update file "VERSION"
* Change '$VERSION = "...";' in "lib/perl/CertNanny.pm" (approx. line 35) to match file "VERSION"
  - this should no longer be necessary in the next release
- Update this file ("Release.checklist.md") if necessary


