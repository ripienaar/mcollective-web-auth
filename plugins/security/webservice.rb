module MCollective
  module Security
    class Webservice < Base
      require 'etc'
      require 'yaml'
      require 'net/http'

      def decodemsg(msg)
        request = deserialize(msg.payload)

        should_process_msg?(msg, request[:requestid])

        unless @initiated_by == :client
          if validrequest?(request)
            request[:ttl] = request[:body][:ttl]
            request[:msgtime] = request[:body][:msgtime]
            request[:requestid] = request[:body][:requestid]
            request[:body] = request[:body][:msg]
          end
          return request
        else
          return request
        end
      end

      def encodereply(sender, msg, requestid, requestcallerid=nil)
        serialize(create_reply(requestid, sender, msg))
      end

      def encoderequest(sender, msg, requestid, filter, target_agent, target_collective, ttl=60)
        request = create_request(requestid, filter, msg, @initiated_by, target_agent, target_collective, ttl)

        secure_request = {:msg => msg,
                          :ttl => ttl,
                          :requestid => requestid,
                          :msgtime => request[:msgtime]}

        secure_request_serialized = serialize(secure_request)
        secure_request_hash = SSL.md5(secure_request_serialized)

        secure_request_parameters = encrypt_via_webservice(requestid, ttl, request[:msgtime], secure_request_hash)

        request[:hash] = secure_request_parameters["hash"]
        request[:callerid] = secure_request_parameters["user"]
        request[:body] = secure_request_serialized

        serialize(request)
      end

      def encrypt_via_webservice(requestid, ttl, msgtime, hash)
        raise "Can not find a security token in ~/.mcollective.token" unless File.exist?(File.expand_path("~/.mcollective.token"))
        raise "~/.mcollective.token should be mode 600" unless ("%o" % File.stat(File.expand_path("~/.mcollective.token")).mode) == "100600"

        token = File.read(File.expand_path("~/.mcollective.token")).chomp

        uri = URI("http://localhost:9292/encrypt?token=%s&requestid=%s&ttl=%s&msgtime=%s&hash=%s" % [token, requestid, ttl, msgtime, hash])
        JSON.parse(Net::HTTP.get(uri))
      end

      def deserialize(data)
        YAML.load(data)
      end

      def serialize(data)
        YAML.dump(data)
      end

      # Validates a incoming request by verifying the signature using the pub key
      # and then RSA decrypting the callerid
      #
      # Updates the request with correct callerid and verified body
      def validrequest?(req)
        ssl = SSL.new("/home/rip/.mcollective.d/rip.pem")

        ssl.verify_signature(req[:hash], SSL.md5(req[:body]), true)

        req[:callerid] = "webuser=%s" % ssl.rsa_decrypt_with_public(ssl.base64_decode(req[:callerid]))
        req[:body] = deserialize(req[:body])

        @stats.validated

        true
      rescue
        @stats.unvalidated
        raise(SecurityValidationFailed, "Received an invalid signature in message")
      end
    end
  end
end
