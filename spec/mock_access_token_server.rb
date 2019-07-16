# frozen_string_literal: true

require 'webrick'

class MockAccessTokenServer
  class Servlet < WEBrick::HTTPServlet::AbstractServlet
    def initialize(server, response = {})
      super(server)
      @response = response
    end

    def do_GET(request, response)
      do_POST(request, response)
    end

    def do_POST(_request, response)
      response.status = @response[:status]
      response['Content-Type'] = @response[:content_type]
      response['WWW-Authenticate'] = @response[:www_authenticate] if @response[:www_authenticate]
      response.body = @response[:body]
    end
  end

  def initialize(paths_and_responses)
    @http_server = WEBrick::HTTPServer.new(Port: 0)
    paths_and_responses.each do |path_and_response|
      @http_server.mount(path_and_response[:path], Servlet, path_and_response[:response])
    end
    @pid = nil
  end

  def base_uri
    "http://localhost:#{@http_server.config[:Port]}"
  end

  def startup
    raise StandardError, 'server has already been started' if @pid

    @pid =
      fork do
        trap('TERM') do
          @http_server.shutdown
          @pid = nil
        end
        trap('INT') do
          @http_server.shutdown
          @pid = nil
        end
        @http_server.start
      end
  end

  def shutdown
    return unless @pid

    Process.kill('TERM', @pid)
    Process.wait(@pid)
    @pid = nil
  end
end
