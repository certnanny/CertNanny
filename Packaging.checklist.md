# Checklist for packaging tagged releases

* Get rid of uncommited changes
  - `git reset --hard`
* Check out the tagged version (in this example v1.1)
  - `git checkout -b build-v1.1 v1.1`
* Get rid of any files not tracked by git (and therefore not part of the tagged release)
  - `git clean -df`
* Verify you have a virgin copy of the code
  - `git status` should say 'nothing to commit, working directory clean'
* Build the package
  - `./make_package.sh`

