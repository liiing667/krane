# Copyright 2020 Appvia Ltd <info@appvia.io>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Understands CLI Commands implementation

module Cli
  module Commands
    extend self

    def report options
      report = Krane::Report::Builder.new(options).build

      if options.ci
        unless report.dangers.empty?
          say "[CI] RBAC test failed. #{report.dangers.size} checks didn't pass...".red
          say JSON.pretty_generate(report.dangers)
          exit 1
        end
        say "[CI] RBAC test passed...".green
      else
        case options.output.to_sym
        when :yaml
          say report.combined.to_yaml
        when :json
          say JSON.pretty_generate(report.combined)
        end
      end

    end

    def dashboard options
      # Finally honours -c: the UI reads the cluster to open from this manifest.
      Krane::Dashboard::Clusters.set_default options.cluster

      token = ENV[Krane::Dashboard::Server::TOKEN_ENV].to_s
      if token.strip.empty?
        raise "#{Krane::Dashboard::Server::TOKEN_ENV} is not set. The dashboard refuses to start without a token: " \
              "export #{Krane::Dashboard::Server::TOKEN_ENV}='<a long random value>' and present it as a bearer token."
      end

      say "---".light_cyan
      say "KRANE DASHBOARD:".light_cyan
      say "http://localhost:#{options.port}".light_cyan
      say "Access requires the #{Krane::Dashboard::Server::TOKEN_ENV} bearer token (value not shown)".light_cyan
      say "---".light_cyan

      Krane::Dashboard::Server.new(
        root:    File.join(Cli::Helpers::APP_ROOT, 'dashboard/compiled'),
        port:    options.port,
        bind:    options.bind,
        token:   token,
        verbose: options.verbose
      ).start
    end

  end
end
