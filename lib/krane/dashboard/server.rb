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

require 'webrick'
require 'openssl'
require 'json'

# Understands how to serve the built dashboard as static files.
#
# The dashboard is a static site: the report writes JSON to disk and the browser
# fetches it. Serving it from Ruby keeps node out of the runtime image and means
# the dashboard command no longer shells out.
#
# Every request is gated behind a bearer token: the server refuses to start
# without one, and a request that does not present it gets a 401 before any
# path is touched, so neither the index, the report JSON, the assets nor an
# error page can confirm or deny anything to an unauthenticated caller.
module Krane
  module Dashboard
    class Server

      DEFAULT_PORT = 8000

      # Defaults to all interfaces because in-cluster the dashboard is reached
      # through a Service. Bind to 127.0.0.1 when running locally.
      DEFAULT_BIND = '0.0.0.0'

      # The build emits no inline scripts and references no external origin, so
      # 'self' covers everything. Styles need 'unsafe-inline' because the graph
      # library sets element styles directly.
      SECURITY_HEADERS = {
        'Content-Security-Policy' => "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'",
        'X-Content-Type-Options'  => 'nosniff',
        'X-Frame-Options'         => 'DENY',
        'Referrer-Policy'         => 'no-referrer'
      }.freeze

      # WEBrick's table predates woff2 and still calls JavaScript application/x-javascript.
      CONTENT_TYPES = {
        '.css'   => 'text/css; charset=utf-8',
        '.html'  => 'text/html; charset=utf-8',
        '.js'    => 'text/javascript; charset=utf-8',
        '.json'  => 'application/json; charset=utf-8',
        '.map'   => 'application/json; charset=utf-8',
        '.png'   => 'image/png',
        '.svg'   => 'image/svg+xml',
        '.woff2' => 'font/woff2',
        '.yaml'  => 'text/yaml; charset=utf-8'
      }.freeze

      DEFAULT_CONTENT_TYPE = 'application/octet-stream'

      # Name of the env var the CLI reads the required token from. Kept as a
      # constant so messages name the configuration knob without ever holding
      # its value.
      TOKEN_ENV = 'KRANE_DASHBOARD_TOKEN'

      # Browsers cannot attach an Authorization header to top-level requests,
      # so the same token is accepted from a cookie. It is never Set-Cookie'd
      # by the server: the caller creates it themselves after port-forwarding.
      TOKEN_COOKIE = 'krane_token'

      UNAUTHORIZED_CACHE = 'no-store'

      # Vite fingerprints everything under /assets, so those URLs can never
      # change meaning. Everything else is rewritten in place by the report loop.
      IMMUTABLE_PREFIX = '/assets/'
      IMMUTABLE_CACHE  = 'public, max-age=31536000, immutable'
      REVALIDATE_CACHE = 'no-cache'

      # @param root [String] directory to serve
      # @param port [Integer] port to listen on
      # @param bind [String] address to bind to
      # @param token [String] bearer token required on every request
      # @param verbose [Boolean] log each request
      def initialize root:, token:, port: DEFAULT_PORT, bind: DEFAULT_BIND, verbose: false
        @root    = File.realpath(root)
        @port    = port
        @bind    = bind
        @token   = validate_token(token)
        @verbose = verbose
      rescue Errno::ENOENT
        raise "Dashboard has not been built: #{root} does not exist"
      end

      # Serves until interrupted.
      #
      # @return [nil]
      def start
        server = build_server
        trap('INT')  { server.shutdown }
        trap('TERM') { server.shutdown }
        server.start
      end

      # Starts serving in a background thread and returns the port in use.
      # Passing port 0 picks a free one, which is what the specs run against.
      #
      # @return [Integer]
      def start_in_background
        @background = build_server
        Thread.new { @background.start }
        @background.listeners.first.addr[1]
      end

      # @return [nil]
      def shutdown
        @background&.shutdown
      end

      private

      def validate_token token
        if token.nil? || token.to_s.strip.empty?
          raise "#{TOKEN_ENV} must be set to a non-empty value: the dashboard is denied to anonymous requests"
        end

        token.to_s.dup.freeze
      end

      def build_server
        TokenServer.new(
          authenticator: method(:authorized?),
          Port:         @port,
          BindAddress:  @bind,
          AccessLog:    @verbose ? nil : [],
          Logger:       WEBrick::Log.new(@verbose ? $stderr : File::NULL)
        ).tap do |server|
          server.mount_proc('/') { |request, response| serve request, response }
        end
      end

      def serve request, response
        SECURITY_HEADERS.each { |header, value| response[header] = value }
        # The connection loop already rejected an unauthenticated request;
        # repeat the check so the mounted handler is safe even if the server
        # construction ever changes.
        return unauthorized(response) unless authorized?(request)

        path = resolve(request.path)
        return not_found(response) if path.nil?

        response['Cache-Control'] = cache_control(request.path)
        response['Content-Type']  = CONTENT_TYPES.fetch(File.extname(path).downcase, DEFAULT_CONTENT_TYPE)

        # The report loop rewrites data files in place, so let the browser
        # revalidate cheaply rather than refetch a chunk it already holds.
        etag = etag_for(path)
        response['ETag'] = etag
        return not_modified(response) if request['If-None-Match'] == etag

        response.status = 200
        response.body = File.open(path, 'rb')
      rescue SystemCallError
        # The file existed a moment ago and does not now: a report regenerated
        # underneath this request and pruned it. That is a 404, not a failure.
        # Reopening is safe once the handle is held, so only the stat and the
        # open can lose this race.
        not_found response
      end

      # WEBrick rejects a malformed or traversal URI while parsing the request,
      # before the mounted handler runs, which would answer with its own 400
      # page and bypass both the token gate and the security headers. This
      # subclass owns the connection loop so such a request is answered with
      # the same uniform 401 as every other unauthenticated one.
      class TokenServer < WEBrick::HTTPServer

        def initialize config = {}, *rest
          @authenticator = config.delete(:authenticator)
          super(config, *rest)
        end

        def run sock
          while true
            request  = create_request(@config)
            response = create_response(@config)
            server   = self
            begin
              wait_for_request(sock)
              begin
                request.parse(sock)
              rescue WEBrick::HTTPStatus::Error => error
                # Parse-level rejections (bad request line, `..` in the URI,
                # oversized headers) never reach the handler. Answer the same
                # gated 401 instead of WEBrick's default HTML error page.
                @logger.error(error.message)
                write_unauthorized(response)
                next
              end

              response.request_method       = request.request_method
              response.request_uri          = request.request_uri
              response.request_http_version = request.http_version
              response.keep_alive           = request.keep_alive?
              server = lookup_server(request) || self
              unless @authenticator.call(request)
                # Gate here as well as in the handler: WEBrick answers OPTIONS
                # (including OPTIONS *) itself, never invoking the mounted proc,
                # so a handler-only check would let method probes through.
                write_unauthorized(response)
                next
              end
              server.service(request, response)
            rescue WEBrick::HTTPStatus::EOFError, WEBrick::HTTPStatus::RequestTimeout
              # Nothing usable arrived: idle keep-alive socket or a truncated
              # request. Closing the connection, like stock WEBrick, leaks no
              # information about the docroot.
              break
            rescue WEBrick::HTTPStatus::Status => status
              response.status = status.code
            rescue StandardError => error
              @logger.error(error)
              response.set_error(error, true)
            ensure
              if request.request_line
                request.fixup if request.keep_alive? && response.keep_alive?
                response.send_response(sock)
                server.access_log(@config, request, response)
              end
            end
            break if @http_version < '1.1'
            break unless request.keep_alive?
            break unless response.keep_alive?
          end
        end

        private

        def wait_for_request sock
          timeout = @config[:RequestTimeout]
          while timeout > 0
            break if sock.to_io.wait_readable(0.5)
            break if @status != :Running

            timeout -= 0.5
          end
          raise WEBrick::HTTPStatus::EOFError if timeout <= 0 || @status != :Running
          raise WEBrick::HTTPStatus::EOFError if sock.eof?
        end

        def write_unauthorized response
          SECURITY_HEADERS.each { |header, value| response[header] = value }
          response.status                 = 401
          response['WWW-Authenticate']    = 'Bearer realm="krane-dashboard"'
          response['Content-Type']        = CONTENT_TYPES['.json']
          response['Cache-Control']       = UNAUTHORIZED_CACHE
          response.keep_alive             = false
          response.body                   = { error: 'unauthorized' }.to_json
        end

      end

      # The check runs before path resolution so a missing token gets the same
      # 401 for a real file, a missing file and a traversal attempt.
      def authorized? request
        presented = presented_token(request)
        return false if presented.nil?

        secure_equals?(@token, presented)
      end

      def presented_token request
        authorization = request['Authorization']
        if authorization
          match = /\ABearer\s+(.+)\z/i.match(authorization.strip)
          return match[1] if match
        end

        request.cookies&.find { |cookie| cookie.name == TOKEN_COOKIE }&.value
      end

      # Lengths are compared first so the timing-safe primitive never has to
      # rescue a length mismatch; either way no token material is logged.
      def secure_equals? expected, actual
        return false unless actual.bytesize == expected.bytesize

        OpenSSL.fixed_length_secure_compare(expected, actual)
      rescue ArgumentError, TypeError
        false
      end

      def unauthorized response
        response.status = 401
        response['WWW-Authenticate'] = 'Bearer realm="krane-dashboard"'
        response['Content-Type']      = CONTENT_TYPES['.json']
        response['Cache-Control']     = UNAUTHORIZED_CACHE
        response.body = { error: 'unauthorized' }.to_json
      end

      # Maps a request path to a file inside the docroot, or nil if it does not
      # resolve to one. Resolving through realpath means neither `..` nor a
      # symlink pointing outside the docroot can escape it.
      def resolve request_path
        candidate = File.expand_path(File.join(@root, request_path))
        candidate = File.join(candidate, 'index.html') if File.directory?(candidate)
        return nil unless File.file?(candidate)

        real = File.realpath(candidate)
        contained?(real) ? real : nil
      rescue ArgumentError, SystemCallError
        # null bytes, unreadable paths, broken symlinks
        nil
      end

      def contained? path
        path.start_with? "#{@root}#{File::SEPARATOR}"
      end

      def cache_control request_path
        request_path.start_with?(IMMUTABLE_PREFIX) ? IMMUTABLE_CACHE : REVALIDATE_CACHE
      end

      def etag_for path
        stat = File.stat(path)
        %("#{stat.mtime.to_i.to_s(16)}-#{stat.size.to_s(16)}")
      end

      def not_found response
        response.status = 404
        response['Content-Type'] = CONTENT_TYPES['.json']
        response['Cache-Control'] = REVALIDATE_CACHE
        response.body = { error: 'not found' }.to_json
      end

      def not_modified response
        response.status = 304
        response.body = ''
      end

    end
  end
end
