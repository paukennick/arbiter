module Jobs
  class Forwarder
    def deliver(client, body)
      client.post(body)
    rescue StandardError # expect: arbiter/ruby.swallowed-rescue-fallback
      false
    end

    def status(client)
      client.get
    rescue StandardError # expect: arbiter/ruby.swallowed-error-to-500
      [500, {}, ["error"]]
    end
  end
end
