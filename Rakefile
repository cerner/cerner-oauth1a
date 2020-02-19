# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rake/clean'
require 'rdoc/task'

# configure clean, clobber tasks
CLEAN << 'build/coverage'
CLEAN << 'build/doc'
CLEAN << 'pkg'
CLOBBER << 'build'
CLOBBER << 'tmp'
CLOBBER << 'Gemfile.lock'

# configure rdoc task
RDoc::Task.new do |rdoc|
  rdoc.main = 'README.md'
  rdoc.markup = 'tomdoc'
  rdoc.rdoc_dir = 'build/doc'
  rdoc.rdoc_files.include('lib/')
end

task(default: [:build])
