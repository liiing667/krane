require 'spec_helper'
require 'tmpdir'
require 'net/http'

describe Krane::Dashboard::Server do

  TOKEN = 'correct-horse-battery-staple'

  around(:each) do |example|
    Dir.mktmpdir do |dir|
      @root = File.realpath(dir)
      FileUtils.mkdir_p File.join(@root, 'assets')
      FileUtils.mkdir_p File.join(@root, 'data', 'default')

      File.write File.join(@root, 'index.html'), '<!doctype html><title>krane</title>'
      File.write File.join(@root, 'assets', 'app-a1b2c3.js'), 'console.log(1)'
      File.write File.join(@root, 'data', 'clusters.json'), '{"default":"default"}'
      File.write File.join(@root, 'data', 'default', 'rbac-findings.json'), '{}'

      example.run
    end
  end

  before(:each) do
    @server = described_class.new(root: @root, port: 0, bind: '127.0.0.1', token: TOKEN)
    @port   = @server.start_in_background
  end

  after(:each) { @server.shutdown }

  # Sends `path` verbatim, so the specs can exercise paths a URI helper would
  # otherwise normalise away.
  def get path, headers = {}
    Net::HTTP.start('127.0.0.1', @port) do |http|
      http.request Net::HTTP::Get.new(path, headers)
    end
  end

  # Sends raw bytes so a request line a well-behaved client would refuse can be
  # exercised. Returns whatever WEBrick managed to parse, or nil for a reset.
  def raw bytes
    socket = TCPSocket.new('127.0.0.1', @port)
    socket.write bytes
    socket.close_write
    Net::HTTPResponse.read_new(Net::BufferedIO.new(socket))
  rescue Errno::ECONNRESET, EOFError, Net::HTTPBadResponse
    nil
  ensure
    socket&.close
  end

  def authorized_headers extra = {}
    { 'Authorization' => "Bearer #{TOKEN}" }.merge(extra)
  end

  describe 'serving files' do

    it 'serves a file from the docroot' do
      response = get '/index.html', authorized_headers

      expect(response.code).to eq '200'
      expect(response.body).to include 'krane'
    end

    it 'serves index.html for the root path' do
      expect(get('/', authorized_headers).body).to include 'krane'
    end

    it 'serves report data' do
      expect(get('/data/default/rbac-findings.json', authorized_headers).code).to eq '200'
    end

    it 'labels JavaScript as text/javascript rather than the x- prefixed legacy type' do
      expect(get('/assets/app-a1b2c3.js', authorized_headers)['content-type']).to eq 'text/javascript; charset=utf-8'
    end

    it 'labels JSON as application/json' do
      expect(get('/data/clusters.json', authorized_headers)['content-type']).to eq 'application/json; charset=utf-8'
    end

    it 'returns 404 for a file that is not there' do
      response = get '/data/missing/rbac-findings.json', authorized_headers

      expect(response.code).to eq '404'
      expect(response['content-type']).to eq 'application/json; charset=utf-8'
    end

    it 'returns 404 when a report regenerates the file out from under the request' do
      # The report loop prunes chunks the new index no longer refers to, so a
      # file can pass the existence check and be gone by the time it is read.
      # Verified live against a container: this used to be a 500.
      allow(File).to receive(:stat).and_call_original
      allow(File).to receive(:stat)
        .with(File.join(@root, 'data', 'default', 'rbac-findings.json'))
        .and_raise(Errno::ENOENT)

      expect(get('/data/default/rbac-findings.json', authorized_headers).code).to eq '404'
    end

    it 'returns 404 when the file disappears between the stat and the open' do
      allow(File).to receive(:open).and_call_original
      allow(File).to receive(:open)
        .with(File.join(@root, 'data', 'default', 'rbac-findings.json'), 'rb')
        .and_raise(Errno::ENOENT)

      expect(get('/data/default/rbac-findings.json', authorized_headers).code).to eq '404'
    end

  end

  describe 'security headers' do

    it 'confines the page to same origin content' do
      expect(get('/index.html', authorized_headers)['content-security-policy'])
        .to eq "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
    end

    it 'stops the browser sniffing a content type' do
      expect(get('/index.html', authorized_headers)['x-content-type-options']).to eq 'nosniff'
    end

    it 'refuses to be framed' do
      expect(get('/index.html', authorized_headers)['x-frame-options']).to eq 'DENY'
    end

    it 'leaks no referrer' do
      expect(get('/index.html', authorized_headers)['referrer-policy']).to eq 'no-referrer'
    end

    it 'sets the headers on an error response too' do
      expect(get('/nope', authorized_headers)['x-content-type-options']).to eq 'nosniff'
    end

  end

  describe 'token gate' do

    it 'refuses to start without a token' do
      expect { described_class.new(root: @root, port: 0, bind: '127.0.0.1', token: nil) }
        .to raise_error(/KRANE_DASHBOARD_TOKEN/)
    end

    it 'refuses to start with a blank token' do
      expect { described_class.new(root: @root, port: 0, bind: '127.0.0.1', token: '   ') }
        .to raise_error(/KRANE_DASHBOARD_TOKEN/)
    end

    it 'answers 401 for the index without a token' do
      expect(get('/').code).to eq '401'
    end

    it 'answers 401 for report JSON without a token' do
      expect(get('/data/default/rbac-findings.json').code).to eq '401'
    end

    it 'answers 401 for fingerprinted assets without a token' do
      expect(get('/assets/app-a1b2c3.js').code).to eq '401'
    end

    it 'answers 401 for a missing path without a token, so existence cannot be probed' do
      expect(get('/data/missing/rbac-findings.json').code).to eq '401'
    end

    it 'answers 401 for a traversal path without a token' do
      expect(get('/../secret.txt').code).to eq '401'
    end

    it 'answers 401 with the security headers for a traversal path without a token' do
      response = get '/%2e%2e%2fsecret.txt'

      expect(response.code).to eq '401'
      expect(response['content-security-policy'])
        .to eq "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
      expect(response['content-type']).to eq 'application/json; charset=utf-8'
      expect(JSON.parse(response.body)).to eq('error' => 'unauthorized')
    end

    it 'answers 401 for a traversal path even when the token is presented' do
      # The URI is rejected before the handler runs; the security response is
      # identical either way, so a valid token cannot probe path validity.
      expect(get('/../secret.txt', authorized_headers).code).to eq '401'
    end

    it 'answers 401 rather than a server error for a malformed request line' do
      response = raw("GARBAGE\r\n\r\n")

      expect(response.code).to eq '401'
      expect(response['content-security-policy']).not_to be_nil
    end

    it 'answers 401 for OPTIONS without a token, even though WEBrick serves OPTIONS itself' do
      response = Net::HTTP.start('127.0.0.1', @port) do |http|
        http.request Net::HTTP::Options.new('/')
      end

      expect(response.code).to eq '401'
      expect(response['content-security-policy']).not_to be_nil
    end

    it 'answers 401 for an OPTIONS * server probe without a token' do
      response = raw("OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n")

      expect(response.code).to eq '401'
    end

    it 'rejects the wrong bearer token' do
      expect(get('/index.html', 'Authorization' => 'Bearer not-the-token').code).to eq '401'
    end

    it 'rejects a malformed Authorization header' do
      expect(get('/index.html', 'Authorization' => 'Basic dXNlcjpwYXNz').code).to eq '401'
      expect(get('/index.html', 'Authorization' => 'Bearer').code).to eq '401'
    end

    it 'accepts the token as a cookie for browser top-level navigation' do
      response = get '/index.html', 'Cookie' => "krane_token=#{TOKEN}"

      expect(response.code).to eq '200'
    end

    it 'rejects a cookie holding the wrong token' do
      response = get '/index.html', 'Cookie' => 'krane_token=not-the-token'

      expect(response.code).to eq '401'
    end

    it 'sends a bearer challenge and a JSON body on 401' do
      response = get '/'

      expect(response['www-authenticate']).to eq 'Bearer realm="krane-dashboard"'
      expect(response['content-type']).to eq 'application/json; charset=utf-8'
      expect(JSON.parse(response.body)).to eq('error' => 'unauthorized')
    end

    it 'keeps the security headers on the 401' do
      response = get '/'

      expect(response['content-security-policy'])
        .to eq "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
      expect(response['x-content-type-options']).to eq 'nosniff'
      expect(response['x-frame-options']).to eq 'DENY'
    end

    it 'tells caches never to store a 401' do
      expect(get('/')['cache-control']).to eq 'no-store'
    end

    it 'sends no ETag on a 401, so an unauthenticated revalidation cannot learn it' do
      expect(get('/data/clusters.json')['etag']).to be_nil
    end

    it 'never echoes the presented token back in the 401 body or headers' do
      response = get '/', 'Authorization' => 'Bearer not-the-token'

      expect(response.body).not_to include 'not-the-token'
      response.each_header do |name, value|
        expect("#{name}: #{value}").not_to include 'not-the-token'
      end
    end

    it 'compares tokens in constant time' do
      # Once in the connection-loop gate, again in the file handler.
      expect(OpenSSL).to receive(:fixed_length_secure_compare).with(TOKEN, TOKEN).twice.and_call_original

      expect(get('/index.html', authorized_headers).code).to eq '200'
    end

    it 'does not call the timing-safe compare when the presented token has a different length' do
      expect(OpenSSL).not_to receive(:fixed_length_secure_compare)

      expect(get('/index.html', 'Authorization' => 'Bearer short').code).to eq '401'
    end

    it 'does not write the token to the request log even in verbose mode' do
      log = StringIO.new
      server = described_class.new(root: @root, port: 0, bind: '127.0.0.1', token: TOKEN, verbose: true)
      allow(WEBrick::Log).to receive(:new).and_return(WEBrick::Log.new(log))
      port = server.start_in_background

      Net::HTTP.start('127.0.0.1', port) do |http|
        http.request Net::HTTP::Get.new('/index.html', authorized_headers)
      end
      sleep 0.2

      expect(log.string).not_to include TOKEN
    ensure
      server&.shutdown
    end

  end

  describe 'path containment' do

    before(:each) do
      @secret = File.join(File.dirname(@root), 'secret.txt')
      File.write @secret, 'top secret'
    end

    after(:each) { FileUtils.rm_f @secret }

    # Traversal is refused twice over: the connection loop turns a WEBrick
    # parse-level `..` rejection into the gated 401, and the handler also
    # resolves through realpath before serving anything. These assert the
    # property rather than which layer answered, so requests carry the token to
    # prove a valid credential still cannot walk out of the docroot.
    def expect_refused path
      response = get path, authorized_headers

      expect(response.code).not_to eq '200'
      expect(response.body.to_s).not_to include 'top secret'
    end

    it 'refuses to walk out of the docroot' do
      expect_refused '/../secret.txt'
    end

    it 'refuses to walk out of the docroot through a nested path' do
      expect_refused '/data/default/../../../secret.txt'
    end

    it 'refuses an escape hidden in percent encoding' do
      expect_refused '/%2e%2e%2fsecret.txt'
    end

    it 'refuses to follow a symlink pointing outside the docroot' do
      File.symlink @secret, File.join(@root, 'leak.txt')

      expect(get('/leak.txt', authorized_headers).code).to eq '404'
    end

    it 'serves a symlink that stays inside the docroot' do
      File.symlink File.join(@root, 'index.html'), File.join(@root, 'alias.html')

      expect(get('/alias.html', authorized_headers).code).to eq '200'
    end

    it 'does not fall over on a null byte in the path' do
      expect(get('/index.html%00.js', authorized_headers).code).to eq '404'
    end

  end

  describe 'caching' do

    it 'lets fingerprinted assets be cached forever' do
      response = get('/assets/app-a1b2c3.js', authorized_headers)
      expect(response['cache-control']).to eq 'public, max-age=31536000, immutable'
    end

    it 'makes the browser revalidate report data, which the report loop rewrites in place' do
      expect(get('/data/clusters.json', authorized_headers)['cache-control']).to eq 'no-cache'
    end

    it 'makes the browser revalidate the entry point' do
      expect(get('/index.html', authorized_headers)['cache-control']).to eq 'no-cache'
    end

    it 'answers a revalidation of unchanged data with 304' do
      etag = get('/data/default/rbac-findings.json', authorized_headers)['etag']
      expect(etag).not_to be_nil

      response = get '/data/default/rbac-findings.json', authorized_headers('If-None-Match' => etag)

      expect(response.code).to eq '304'
    end

    it 'sends the file again once it has changed' do
      etag = get('/data/default/rbac-findings.json', authorized_headers)['etag']

      path = File.join(@root, 'data', 'default', 'rbac-findings.json')
      File.write path, '{"summary":{}}'
      FileUtils.touch path, mtime: Time.now + 60

      expect(get('/data/default/rbac-findings.json', authorized_headers('If-None-Match' => etag)).code).to eq '200'
    end

  end

  describe 'startup' do

    it 'fails with a clear message when the dashboard has not been built' do
      expect { described_class.new(root: File.join(@root, 'nope'), token: TOKEN) }
        .to raise_error(/has not been built/)
    end

  end

end
