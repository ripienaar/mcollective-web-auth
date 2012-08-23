#!/usr/bin/ruby

require 'rubygems'
require 'sinatra'
require 'pp'
require 'mcollective'

SALT = "Roophoojaegooviechoniegeelaejo"

helpers do
def protected!
    unless authorized?
      response['WWW-Authenticate'] = %(Basic realm="Restricted Area")
      throw(:halt, [401, "Not authorized\n"])
    end
  end

  def authorized?
    @auth ||=  Rack::Auth::Basic::Request.new(request.env)
    @auth.provided? && @auth.basic? && @auth.credentials && @auth.credentials == ['admin', 'admin']
  end

  def authenticated_user
    @auth ||=  Rack::Auth::Basic::Request.new(request.env)

    if @auth.provided? && @auth.basic?
      return @auth.credentials.first
    else
      return "-"
    end
  end
end

# returns:
#   - a signature made with the the private key of the request and secure parameter
#   - the username making this request AES encrypted
#   - the AES key used to decrypt the username, RSA encrypted
get '/encrypt' do
  if params[:token]
    tokenfile = "/tmp/tokens/#{params[:token]}.txt"
    now = Time.now.to_i

    puts tokenfile

    if File.exist?(tokenfile)
      valid_from, valid_until, user, token = File.read(tokenfile).chomp.split(",")

      throw(:halt, [500, "Token is not valid yet"]) if valid_from.to_i> now
      throw(:halt, [500, "Token has expired"]) if valid_until.to_i < now
      throw(:halt, [500, "Token does not match"]) unless token == request[:token]

      throw(:halt, [500, "Please supply a request id"]) unless params[:requestid]          # unique per mcollective request
      throw(:halt, [500, "Please supply a request ttl"]) unless params[:ttl]               # cant tamper with the TTLs
      throw(:halt, [500, "Please supply a request message time"]) unless params[:msgtime]  # TTLs and msgtime go together
      throw(:halt, [500, "Please supply a request hash"]) unless params[:hash]             # a md5 of the request being approved
                                                                                           # an attacker cant change the request post auth

      ssl = MCollective::SSL.new(nil, "/home/rip/.mcollective.d/rip-private.pem")

      signed = ssl.sign({"requestid" => params[:requestid],
                         "ttl" => params[:ttl],
                         "msgtime" => params[:msgtime],
                         "hash" => params[:hash],
                         "caller" => authenticated_user}.to_json, true)

      callerid = ssl.base64_encode(ssl.rsa_encrypt_with_private(user))

      {"hash" => signed,             # openssl signature using my private key
       "user" => callerid}.to_json   # RSA encrypted "rip"
    else
      throw(:halt, [401, "Not a valid token"])
    end
  else
    throw(:halt, [401, "No token received"])
  end
end

get '/authenticate' do
  protected!

  valid_from = Time.now
  valid_to = (valid_from + 3600)
  user = authenticated_user

  token = MCollective::SSL.uuid("#{SALT}#{user}#{valid_from.to_i}#{valid_to.to_i}")

  open("/tmp/tokens/#{token}.txt", "w") {|f| f.puts("%s,%s,%s,%s" % [valid_from.to_i, valid_to.to_i, user, token]) }

  {"token" => token, "valid_till" => valid_to.to_i}.to_json
end
