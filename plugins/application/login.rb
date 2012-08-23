class MCollective::Application::Login<MCollective::Application
  description "Log into the MCollective Authentication service"

  exclude_argument_sections "common", "filter", "rpc"

  usage "mco login"

  def main
    require 'highline'
    require 'net/http'
    require 'tempfile'

    h = HighLine.new

    user = h.ask("User Name: ")
    pass = h.ask("Password: ") {|q| q.echo = "*"}
    puts "Performing two factor authentication against webservice and duo security...."

    uri = URI("http://localhost:9292/authenticate")

    req = Net::HTTP::Get.new(uri.request_uri)

    req.basic_auth user, pass

    res = Net::HTTP.start(uri.host, uri.port) do |http|
      http.request(req)
    end

    begin
      token = JSON.parse(res.body)
    rescue
      abort res.body
    end

    File.open(File.expand_path("~/.mcollective.token"), "w") {|f| f.puts token["token"]}
    File.chmod(0600, File.expand_path("~/.mcollective.token"))

    puts "Token saved to %s valid till %s" % [File.expand_path("~/.mcollective.token"), Time.at(Integer(token["valid_till"]))]
  end
end
