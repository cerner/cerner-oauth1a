# How to Release

This project is hosted on RubyGems.  You can see it [here](https://rubygems.org/gems/cerner-oauth1a/).

Releasing the project requires these steps:

0. Set the version number in the file `lib/cerner/oauth1a/version.rb`
1. Run `bin/rspec` and verify that no tests fail
2. Run `bin/rake build` and verify that the gem packages without a failure
2. Use a GitHub [project release][github-release-url] to release the project and tag (be sure it follows [semver][semantic-versioning])
3. Run `gem push pkg/cerner-oauth1a-x.x.x.gem` to release the gem to RubyGems
4. Update `master` to a new minor version

[project-url]: https://github.com/cerner/cerner-oauth1a/
[semantic-versioning]: http://semver.org/
[github-release-url]: https://help.github.com/articles/creating-releases/
