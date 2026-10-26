module Jobs
  class Forwarder
    def initialize(logger)
      @logger = logger
    end

    def deliver(client, body)
      client.post(body)
    rescue StandardError => e
      @logger.error("delivery failed: #{e.message}")
      false
    end

    def status(client)
      client.get
    rescue StandardError => e
      @logger.error("status failed: #{e.message}")
      [500, {}, ["error"]]
    end
  end
end
